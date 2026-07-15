"""Computes the scores shown in the risk-assessment section of every
report. These are heuristic, transparent, and rule-based (NOT AI-generated)
so an analyst can audit exactly why a score came out the way it did."""
from __future__ import annotations

from core.schema import EntityType, Investigation, RiskAssessment


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def compute_risk(investigation: Investigation) -> RiskAssessment:
    entities = investigation.entities
    notes: list[str] = []

    total_planned = max(1, len(investigation.tool_results))
    successful = sum(1 for tr in investigation.tool_results if tr.success)
    completeness = _clamp(successful / total_planned)

    social_count = sum(1 for e in entities if e.type == EntityType.SOCIAL_ACCOUNT)
    email_count = sum(1 for e in entities if e.type == EntityType.EMAIL)
    subdomain_count = sum(1 for e in entities if e.type == EntityType.SUBDOMAIN)
    tech_count = sum(1 for e in entities if e.type in (EntityType.TECHNOLOGY, EntityType.FRAMEWORK))
    url_count = sum(1 for e in entities if e.type == EntityType.URL)

    public_presence = _clamp((social_count * 0.15) + (email_count * 0.1))
    repo_exposure = _clamp(sum(1 for e in entities if "github" in e.value.lower()) * 0.2)
    tech_exposure = _clamp(tech_count * 0.1 + url_count * 0.03)
    exposure = _clamp(0.4 * public_presence + 0.3 * repo_exposure + 0.3 * tech_exposure)

    confidences = [e.confidence for e in entities] or [0.0]
    avg_confidence = sum(confidences) / len(confidences)

    if subdomain_count > 10:
        notes.append(f"Large subdomain footprint ({subdomain_count}) increases attack surface visibility.")
    if repo_exposure > 0.4:
        notes.append("Multiple public code repositories linked — review for accidental secret exposure.")
    if not investigation.entities:
        notes.append("No entities were collected; scores below are not meaningful yet.")

    return RiskAssessment(
        confidence_score=round(avg_confidence, 2),
        exposure_score=round(exposure, 2),
        investigation_completeness=round(completeness, 2),
        repository_exposure=round(repo_exposure, 2),
        technology_exposure=round(tech_exposure, 2),
        public_presence_score=round(public_presence, 2),
        notes=notes,
    )
