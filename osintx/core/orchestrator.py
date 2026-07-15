"""The Orchestrator ties everything together for a single `osintx
investigate` invocation: picks the right module for the target type, runs
it, then runs normalization -> timeline -> risk -> (optional) AI engine,
producing one finished Investigation object ready for report generation."""
from __future__ import annotations

from datetime import datetime, timezone

from ai.engine import AIEngine
from config.loader import AppConfig
from core.schema import Investigation
from core.tool_registry import ToolRegistry
from engines.normalization import normalize_entities
from engines.risk import compute_risk
from engines.timeline import build_timeline
from modules.company_module import CompanyModule
from modules.domain_module import DomainModule
from modules.email_module import EmailModule
from modules.image_module import ImageModule
from modules.ip_module import IPModule
from modules.person_module import PersonModule
from modules.username_module import UsernameModule

MODULE_MAP = {
    "person": PersonModule,
    "username": UsernameModule,
    "email": EmailModule,
    "domain": DomainModule,
    "ip": IPModule,
    "company": CompanyModule,
    "image": ImageModule,
}


class Orchestrator:
    def __init__(self, config: AppConfig):
        self.config = config
        self.tool_registry = ToolRegistry(configured_paths=config.tools)

    def investigate(self, target_type: str, target_value: str, use_ai: bool = True, **kwargs) -> Investigation:
        module_cls = MODULE_MAP.get(target_type)
        if module_cls is None:
            raise ValueError(f"Unsupported target type: '{target_type}'")

        investigation = Investigation(target_type=target_type, target_value=target_value)
        module = module_cls(self.tool_registry, timeout=self.config.general.timeout_seconds)

        try:
            module.run(target_value, investigation, **kwargs)
        except Exception as exc:  # noqa: BLE001 — module errors shouldn't crash the CLI
            investigation.warnings.append(f"Module execution error: {exc}")

        investigation.entities = normalize_entities(investigation.entities)
        investigation.timeline = build_timeline(investigation.entities, investigation.tool_results)
        investigation.risk = compute_risk(investigation)

        if use_ai:
            ai_engine = AIEngine(self.config.ai)
            ai_engine.enrich(investigation)

        investigation.completed_at = datetime.now(timezone.utc).isoformat()
        return investigation
