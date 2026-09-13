from __future__ import annotations

import re
from urllib.parse import urlencode, urlsplit
from core.schema import Entity, EntityType, Investigation, ToolResult, ResultStatus
from modules.base import InvestigationModule
from utils.http import request_json, SourceError
from utils.validators import validate_company, validate_url, ValidationError


class CompanyModule(InvestigationModule):
    target_type = 'company'

    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        target = validate_company(target)
        investigation.add_suggestion('Official site search', 'https://www.google.com/search?' + urlencode({'q': '"' + target + '" official site'}))
        investigation.add_suggestion('Crunchbase search', 'https://www.crunchbase.com/textsearch?' + urlencode({'q': target}))
        slug = target.lower().replace(' ', '-')
        if self.offline or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?', slug):
            investigation.add_tool_result(ToolResult('github_api', target, True, status=ResultStatus.NOT_REQUIRED, error='Offline or no syntactically valid organization-name candidate'))
            return
        url = f'https://api.github.com/orgs/{slug}/repos'
        try:
            repos = request_json('GET', url, params={'per_page': 30}, headers={'Accept': 'application/vnd.github+json'}, timeout=self.timeout)
            if not isinstance(repos, list):
                raise SourceError(ResultStatus.API_ERROR, 'Unexpected GitHub response shape')
            entities = []
            for repo in repos:
                if not isinstance(repo, dict) or not isinstance(repo.get('html_url'), str) or not isinstance(repo.get('owner'), dict) or not isinstance(repo['owner'].get('login'), str):
                    raise SourceError(ResultStatus.API_ERROR, 'Malformed GitHub repository record')
                try:
                    repo_url = validate_url(repo['html_url'])
                except ValidationError as exc:
                    raise SourceError(ResultStatus.API_ERROR, 'Invalid GitHub repository URL') from exc
                parts = urlsplit(repo_url)
                if parts.hostname != 'github.com' or not parts.path.lower().startswith('/' + slug + '/') or repo['owner'].get('login', '').lower() != slug:
                    raise SourceError(ResultStatus.API_ERROR, 'GitHub repository owner mismatch')
                entities.append(Entity(EntityType.URL, repo_url, 'github_api', status=ResultStatus.UNVERIFIED, url=repo_url,
                                       evidence=f'GitHub API returned this repository for candidate organization {slug}',
                                       metadata={'language': repo.get('language'), 'stars': repo.get('stargazers_count'), 'candidate_org': slug},
                                       confidence_basis='Repository returned by GitHub; relationship between candidate organization and company is UNVERIFIED'))
            investigation.add_tool_result(ToolResult('github_api', target, True, entities=entities, status=ResultStatus.UNVERIFIED if entities else ResultStatus.NOT_FOUND))
            investigation.warnings.append('GitHub slug derived from company name is only a candidate; company affiliation is UNVERIFIED. At most 30 repositories are shown.')
        except SourceError as exc:
            investigation.add_tool_result(ToolResult('github_api', target, exc.status == ResultStatus.NOT_FOUND, status=exc.status, error=str(exc)))
