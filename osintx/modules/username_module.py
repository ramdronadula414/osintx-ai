from __future__ import annotations

import tempfile
from core.schema import Investigation, ToolResult, ResultStatus
from modules.base import InvestigationModule
from utils.shell import run_command
from utils.validators import validate_username


class UsernameModule(InvestigationModule):
    target_type = 'username'

    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        target = validate_username(target)
        self.run_tool('sherlock', target, investigation)
        if self.offline:
            investigation.add_tool_result(ToolResult('maigret', target, True, status=ResultStatus.NOT_REQUIRED, error='Offline mode'))
        elif self.tool_registry.is_available('maigret'):
            with tempfile.TemporaryDirectory(prefix='osintx-maigret-') as workdir:
                command = run_command([self.tool_registry.path_for('maigret'), target, '--json', 'simple'], timeout=self.timeout, cwd=workdir)
            investigation.add_tool_result(ToolResult.from_command('maigret', target, command, status=ResultStatus.UNKNOWN))
            investigation.warnings.append('Maigret output is diagnostic only; no verified parser is implemented.')
        else:
            investigation.add_tool_result(ToolResult('maigret', target, False, status=ResultStatus.TOOL_UNAVAILABLE, error='Optional tool not installed'))
        investigation.warnings.append('Sherlock matches are UNVERIFIED candidates. HTTP errors, challenges, redirects, and login pages are never confirmation of an account or identity.')
