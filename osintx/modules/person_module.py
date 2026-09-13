from __future__ import annotations

from urllib.parse import urlencode
from core.schema import Investigation
from modules.base import InvestigationModule
from utils.validators import validate_name


class PersonModule(InvestigationModule):
    target_type = 'person'

    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        target = validate_name(target)
        for label, base in [('Google', 'https://www.google.com/search'), ('Bing', 'https://www.bing.com/search'), ('DuckDuckGo', 'https://duckduckgo.com/')]:
            investigation.add_suggestion(label, base + '?' + urlencode({'q': '"' + target + '"'}))
        investigation.add_suggestion('GitHub users', 'https://github.com/search?' + urlencode({'q': target, 'type': 'users'}))
        investigation.add_suggestion('LinkedIn people', 'https://www.linkedin.com/search/results/people/?' + urlencode({'keywords': target}))
        investigation.warnings.append('Person search provides search suggestions only. No person, profile, or identity has been verified.')
