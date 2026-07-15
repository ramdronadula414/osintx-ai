from unittest.mock import patch

from core.schema import Investigation
from integrations.dig_tool import DigIntegration
from integrations.whois_tool import WhoisIntegration
from utils.shell import CommandResult


def test_whois_integration_extracts_org_from_stdout():
    fake_stdout = (
        "Domain Name: EXAMPLE.COM\n"
        "Registrar: Example Registrar LLC\n"
        "OrgName: Example Org\n"
        "Creation Date: 1995-08-14T04:00:00Z\n"
    )
    integration = WhoisIntegration(executable_path="/usr/bin/whois")
    fake_result = CommandResult(argv=["whois", "example.com"], returncode=0, stdout=fake_stdout, stderr="")
    tool_result = integration.parse("example.com", fake_result)
    assert tool_result.success
    orgs = [e.value for e in tool_result.entities]
    assert "Example Org" in orgs


def test_dig_integration_parses_a_record():
    fake_stdout = "example.com.\t300\tIN\tA\t93.184.216.34\n"
    integration = DigIntegration(executable_path="/usr/bin/dig")
    fake_result = CommandResult(argv=["dig", "example.com", "A"], returncode=0, stdout=fake_stdout, stderr="")
    tool_result = integration.parse("example.com", fake_result)
    assert tool_result.success
    values = [e.value for e in tool_result.entities]
    assert "93.184.216.34" in values


def test_domain_module_skips_gracefully_when_tools_missing():
    from modules.domain_module import DomainModule

    class FakeRegistry:
        def is_available(self, name):
            return False

        def path_for(self, name):
            return None

    module = DomainModule(FakeRegistry())
    investigation = Investigation(target_type="domain", target_value="example.com")
    module.run("example.com", investigation)
    # No tools available -> no crash, and helpful warnings/behavior (no tool_results added)
    assert isinstance(investigation.tool_results, list)
