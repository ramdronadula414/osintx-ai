from __future__ import annotations

from core.schema import Entity, EntityType, Investigation, ToolResult
from modules.base import InvestigationModule
from utils.logger import get_logger
from utils.validators import validate_name

log = get_logger(__name__)


class PersonModule(InvestigationModule):
    """Correlates a full name against public sources theHarvester/Sherlock
    already touch, plus a generated set of public search-engine query URLs
    the analyst can open manually (no scraping of search-result pages,
    which would violate most search engines' terms of service)."""
    target_type = "person"

    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        target = validate_name(target)
        quoted = target.replace(" ", "+")

        search_urls = [
            f"https://www.google.com/search?q=%22{quoted}%22",
            f"https://www.bing.com/search?q=%22{quoted}%22",
            f"https://duckduckgo.com/?q=%22{quoted}%22",
            f"https://github.com/search?q={quoted}&type=users",
            f"https://www.linkedin.com/search/results/people/?keywords={quoted}",
        ]
        entities = [
            Entity(type=EntityType.URL, value=url, source="person_module", confidence=0.3,
                   metadata={"kind": "manual_search_suggestion"})
            for url in search_urls
        ]

        investigation.add_tool_result(ToolResult(
            tool="person_module", target=target, success=True,
            entities=entities, raw_output="",
        ))
        investigation.warnings.append(
            "Person search generates manual-review search-engine URLs rather than scraping "
            "results directly, to respect each platform's terms of service. Open the links "
            "above to review results yourself, or supply a known username/email for deeper "
            "automated correlation."
        )
