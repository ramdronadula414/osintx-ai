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


@dataclass
class Entity:
    type: EntityType
    value: str
    source: str                       # which tool/module produced this
    confidence: float = 0.7           # 0.0 - 1.0
    first_seen: Optional[str] = None  # ISO timestamp, if known
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])

    def dedupe_key(self) -> tuple:
        return (self.type.value, self.value.strip().lower())


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

    def add_tool_result(self, result: ToolResult):
        self.tool_results.append(result)
        self.entities.extend(result.entities)

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
