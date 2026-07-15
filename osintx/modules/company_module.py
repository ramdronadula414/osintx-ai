from __future__ import annotations

import requests

from core.schema import Entity, EntityType, Investigation, ToolResult
from modules.base import InvestigationModule
from utils.logger import get_logger

log = get_logger(__name__)


class CompanyModule(InvestigationModule):
    """Looks up a company's public GitHub organization (repos, languages)
    and generates manual-review links for its public web presence."""
    target_type = "company"

    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        org_slug = target.strip().lower().replace(" ", "-")

        entities = []
        error = None
        try:
            resp = requests.get(f"https://api.github.com/orgs/{org_slug}/repos",
                                 params={"per_page": 30}, timeout=15,
                                 headers={"Accept": "application/vnd.github+json"})
            if resp.status_code == 200:
                for repo in resp.json():
                    entities.append(Entity(
                        type=EntityType.URL, value=repo.get("html_url", ""),
                        source="github_api", confidence=0.8,
                        metadata={"language": repo.get("language"), "stars": repo.get("stargazers_count")},
                    ))
                    if repo.get("language"):
                        entities.append(Entity(
                            type=EntityType.LANGUAGE, value=repo["language"],
                            source="github_api", confidence=0.6,
                        ))
            elif resp.status_code == 404:
                investigation.warnings.append(f"No public GitHub organization found at '{org_slug}'.")
            else:
                error = f"GitHub API returned HTTP {resp.status_code}"
        except requests.RequestException as exc:
            error = str(exc)

        investigation.add_tool_result(ToolResult(
            tool="github_api", target=target, success=error is None,
            entities=entities, raw_output="", error=error,
        ))

        quoted = target.replace(" ", "+")
        manual_links = [
            Entity(type=EntityType.URL, value=f"https://www.google.com/search?q=%22{quoted}%22+official+site",
                   source="company_module", confidence=0.3, metadata={"kind": "manual_search_suggestion"}),
            Entity(type=EntityType.URL, value=f"https://www.crunchbase.com/textsearch?q={quoted}",
                   source="company_module", confidence=0.3, metadata={"kind": "manual_search_suggestion"}),
        ]
        investigation.add_tool_result(ToolResult(
            tool="company_module", target=target, success=True, entities=manual_links, raw_output="",
        ))
