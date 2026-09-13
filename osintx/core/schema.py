"""Unified data schema shared by every module, engine, and report generator.

Every OSINT module — regardless of which underlying Linux tool produced the
raw data — normalizes its findings into these dataclasses before anything
downstream (AI engine, risk engine, report generator) touches them. This is
what lets a report combine Sherlock + theHarvester + whois output into one
coherent set of tables instead of N incompatible formats.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class EntityType(str, Enum):
    PERSON = "person"
    ORGANIZATION = "organization"
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    TECHNOLOGY = "technology"
    LANGUAGE = "language"
    FRAMEWORK = "framework"
    CERTIFICATE = "certificate"
    SOCIAL_ACCOUNT = "social_account"
    DNS_RECORD = "dns_record"
    METADATA = "metadata"
    TEXT = "text"
    FILE_HASH = "file_hash"
    NETWORK_SERVICE = "network_service"


class ResultStatus(str, Enum):
    FOUND = "FOUND"
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    UNVERIFIED = "UNVERIFIED"
    NOT_FOUND = "NOT FOUND"
    UNKNOWN = "UNKNOWN"
    TOOL_UNAVAILABLE = "TOOL UNAVAILABLE"
    API_ERROR = "API ERROR"
    NETWORK_ERROR = "NETWORK ERROR"
    PERMISSION_ERROR = "PERMISSION ERROR"
    RATE_LIMITED = "RATE LIMITED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    NOT_REQUIRED = "NOT REQUIRED"


FAILURE_STATUSES = {ResultStatus.TOOL_UNAVAILABLE, ResultStatus.API_ERROR,
                    ResultStatus.NETWORK_ERROR, ResultStatus.PERMISSION_ERROR,
                    ResultStatus.RATE_LIMITED, ResultStatus.TIMEOUT, ResultStatus.ERROR}


@dataclass
class Entity:
    type: EntityType
    value: str
    source: str                       # which tool/module produced this
    confidence: Optional[float] = None           # 0.0 - 1.0
    first_seen: Optional[str] = None  # ISO timestamp, if known
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])

    status: ResultStatus = ResultStatus.UNVERIFIED
    evidence: str = ""
    url: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence_basis: str = "Not assessed; no probability estimate is implied"

    def __post_init__(self):
        self.status = ResultStatus(self.status)
        # Input and suggestions are never independent evidence.
        if self.source == "input" or str(self.metadata.get("kind", "")).startswith("manual_"):
            self.status = ResultStatus.UNVERIFIED
            self.confidence = None
        if self.status == ResultStatus.CONFIRMED and not self.evidence:
            self.status = ResultStatus.UNVERIFIED
        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise ValueError("Confidence must be between 0 and 1")

    def dedupe_key(self) -> tuple:
        from utils.validators import validate_url, validate_domain, validate_ip, validate_email, ValidationError
        value = self.value.strip()
        try:
            if self.type in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
                value = validate_domain(value)
            elif self.type in (EntityType.URL, EntityType.SOCIAL_ACCOUNT):
                value = validate_url(value)  # Preserve case-sensitive paths and queries.
            elif self.type == EntityType.IP:
                value = validate_ip(value)
            elif self.type == EntityType.EMAIL:
                value = validate_email(value)  # Preserve potentially case-sensitive local part.
            elif self.type in (EntityType.ORGANIZATION, EntityType.PERSON):
                value = value.casefold()
            elif self.type == EntityType.PHONE:
                value = ''.join(c for c in value if c.isdigit() or c == '+')
        except ValidationError:
            pass  # Arbitrary metadata/text is not silently transformed into a valid target.
        context = tuple(str(self.metadata.get(k, '')) for k in ('record', 'owner', 'kind', 'target'))
        return (self.type.value, value, self.status.value, context)


@dataclass
class ToolResult:
    """Raw (but already-parsed) output from a single external tool run."""
    tool: str
    target: str
    success: bool
    entities: list[Entity] = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_seconds: float = 0.0
    status: Optional[ResultStatus] = None
    raw_stderr: str = ""

    def __post_init__(self):
        if self.status is None:
            self.status = (ResultStatus.FOUND if any(e.status == ResultStatus.CONFIRMED for e in self.entities)
                           else ResultStatus.UNVERIFIED if self.entities else ResultStatus.UNKNOWN) if self.success else ResultStatus.ERROR
        self.status = ResultStatus(self.status)
        if self.status in FAILURE_STATUSES:
            self.success = False
        if not self.success:
            self.entities = []  # Failed/partial output is diagnostic only, never a discovery.

    @classmethod
    def from_command(cls, tool, target, command, entities=None, **kwargs):
        status = None
        error = None
        if command.timed_out:
            status, error = ResultStatus.TIMEOUT, "Tool exceeded its time limit"
        elif command.output_limited:
            status, error = ResultStatus.ERROR, "Tool exceeded its output limit; partial output discarded"
        elif command.returncode == 127:
            status, error = ResultStatus.TOOL_UNAVAILABLE, "Executable or working directory not found"
        elif command.returncode == 126:
            status, error = ResultStatus.PERMISSION_ERROR, "Permission denied executing tool"
        elif not command.ok:
            status, error = ResultStatus.ERROR, f"Tool exited with code {command.returncode}"
        requested_status = kwargs.pop("status", None)
        return cls(tool, target, command.ok, entities=entities or [], raw_output=command.stdout, raw_stderr=command.stderr,
                   status=status or requested_status, error=error, **kwargs)


@dataclass
class TimelineEvent:
    timestamp: str
    description: str
    source: str
    entity_ids: list[str] = field(default_factory=list)


@dataclass
class RiskAssessment:
    confidence_score: float = 0.0
    exposure_score: float = 0.0
    investigation_completeness: float = 0.0
    repository_exposure: float = 0.0
    technology_exposure: float = 0.0
    public_presence_score: float = 0.0
    notes: list[str] = field(default_factory=list)


@dataclass
class Investigation:
    """Top-level container for one `osintx investigate` run."""
    target_type: str
    target_value: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    tool_results: list[ToolResult] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    risk: RiskAssessment = field(default_factory=RiskAssessment)
    ai_summary: Optional[str] = None
    ai_technical_summary: Optional[str] = None
    ai_recommendations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    suggestions: list[dict[str, str]] = field(default_factory=list)
    ai_status: ResultStatus = ResultStatus.NOT_REQUIRED

    def add_tool_result(self, result: ToolResult):
        if not result.success or result.status in FAILURE_STATUSES:
            result.entities = []
        self.tool_results.append(result)
        self.entities.extend(result.entities)

    def entity_groups(self):
        return [("CONFIRMED FINDINGS", [e for e in self.entities if e.status == ResultStatus.CONFIRMED]),
                ("UNVERIFIED FINDINGS", [e for e in self.entities if e.status != ResultStatus.CONFIRMED])]

    def add_suggestion(self, label: str, url: str):
        self.suggestions.append({"label": label, "url": url, "status": "UNVERIFIED", "kind": "search suggestion"})

    def to_dict(self) -> dict:
        import dataclasses

        def conv(obj):
            if dataclasses.is_dataclass(obj):
                return {k: conv(v) for k, v in dataclasses.asdict(obj).items()}
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, list):
                return [conv(v) for v in obj]
            if isinstance(obj, dict):
                return {k: conv(v) for k, v in obj.items()}
            return obj

        return conv(self)
