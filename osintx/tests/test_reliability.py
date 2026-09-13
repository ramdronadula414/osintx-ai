import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests
from typer.testing import CliRunner
from config.loader import AppConfig, AIConfig, load_config, ConfigError
from core.schema import Entity, EntityType, Investigation, ToolResult, ResultStatus as S
from core.orchestrator import Orchestrator
from core.tool_registry import ToolRegistry
from utils.shell import CommandResult, run_command
from utils.validators import ValidationError, validate_email, validate_domain, validate_username, validate_ip, validate_name, validate_url, validate_phone
from utils.http import request_json, SourceError
from integrations.dig_tool import DigIntegration
from integrations.sherlock_tool import SherlockIntegration
from integrations.whois_tool import WhoisIntegration
from integrations.theharvester_tool import TheHarvesterIntegration
from integrations.exiftool_tool import ExifToolIntegration
from integrations.nmap_tool import NmapIntegration
from engines.normalization import normalize_entities
from engines.risk import compute_risk
from ai.engine import AIEngine, _facts_block
from ai.providers.groq import GroqProvider
from ai.providers.gemini import GeminiProvider
from ai.providers.ollama import OllamaProvider
from ai.provider import AIProviderError
from cli import app


@pytest.mark.parametrize('validator,value', [
    (validate_email, 'a..b@example.com'), (validate_email, '.a@example.com'), (validate_email, 'a@-bad.com'),
    (validate_email, 'a@example..com'), (validate_email, 'a' * 65 + '@example.com'),
    (validate_domain, 'https://example.com/a'), (validate_domain, 'example.com:443'),
    (validate_domain, '1.2.3.4'), (validate_domain, '-bad.com'), (validate_domain, 'x.123'),
    (validate_username, '--help'), (validate_username, '-alice'), (validate_username, 'a\x00b'),
    (validate_username, 'a\nb'), (validate_ip, '999.1.2.3'), (validate_ip, 'fe80::1%eth0'),
    (validate_url, 'https://user:password@example.com'), (validate_url, 'javascript:alert(1)'),
    (validate_url, 'https://example.com:abc'), (validate_phone, '------'),
])
def test_invalid_inputs(validator, value):
    with pytest.raises(ValidationError):
        validator(value)


def test_normalization_unicode_and_case():
    assert validate_domain('BÜCHER.de.') == 'xn--bcher-kva.de'
    assert validate_email('Alice@EXAMPLE.COM') == 'Alice@example.com'
    assert validate_ip('2001:0db8::1') == '2001:db8::1'
    assert validate_name('రామ అంజనేయులు')
    assert validate_url('https://EXAMPLE.com:443/Case?q=Yes#fragment') == 'https://example.com/Case?q=Yes'


def test_invalid_target_never_reaches_module(monkeypatch):
    run = Mock()
    monkeypatch.setattr('modules.domain_module.DomainModule.run', run)
    with pytest.raises(ValidationError):
        Orchestrator(AppConfig()).investigate('domain', 'bad;input', use_ai=False)
    run.assert_not_called()


@pytest.mark.parametrize('integration,text', [
    (DigIntegration, 'example.com. 300 IN A 192.0.2.1'),
    (SherlockIntegration, '[+] GitHub: https://github.com/alice'),
    (WhoisIntegration, 'OrgName: Example Org'),
    (TheHarvesterIntegration, '[*] Emails found: 1\nalice@example.com'),
    (ExifToolIntegration, '[{"EXIF:Make":"Camera"}]'),
    (NmapIntegration, '80/tcp open http'),
])
def test_failed_commands_never_emit_findings(integration, text):
    result = integration('missing').parse('example.com', CommandResult([], 1, text, 'error'))
    assert not result.success and result.entities == [] and result.status == S.ERROR


@pytest.mark.parametrize('command,status', [
    (CommandResult([], 127, '', ''), S.TOOL_UNAVAILABLE),
    (CommandResult([], 126, '', ''), S.PERMISSION_ERROR),
    (CommandResult([], -9, 'partial', '', timed_out=True), S.TIMEOUT),
    (CommandResult([], -9, 'partial', '', output_limited=True), S.ERROR),
])
def test_command_status_conversion(command, status):
    result = ToolResult.from_command('tool', 'target', command, status=S.UNKNOWN)
    assert result.status == status and result.entities == []


def test_defense_in_depth_failed_tool_entities():
    entity = Entity(EntityType.EMAIL, 'a@example.com', 'bad', status=S.CONFIRMED, evidence='partial')
    result = ToolResult('bad', 'example.com', False, [entity])
    result.entities.append(entity)  # A third-party plugin attempts to add results after construction.
    inv = Investigation('domain', 'example.com')
    inv.add_tool_result(result)
    assert inv.entities == [] and result.entities == []


@pytest.mark.parametrize('text', ['Error: https://github.com/alice', '[!] 403 https://github.com/alice',
                                  '[+] Site: https://example.com/', '[+] Site: https://example.com/login/alice',
                                  '[+] Site: https://example.com/another', '[+] Site: https://example.com/challenge/alice'])
def test_sherlock_rejects_errors_generic_pages_and_unrelated_urls(text):
    result = SherlockIntegration('sherlock').parse('alice', CommandResult([], 0, text, ''))
    assert result.entities == [] and result.status == S.UNKNOWN


def test_sherlock_candidates_not_confirmed():
    result = SherlockIntegration('sherlock').parse('alice', CommandResult([], 0, '[+] GitHub: https://github.com/alice', ''))
    assert len(result.entities) == 1 and result.entities[0].status == S.UNVERIFIED
    assert result.entities[0].confidence is None


@pytest.mark.parametrize('rcode,status', [('NXDOMAIN', S.NOT_FOUND), ('SERVFAIL', S.NETWORK_ERROR), ('REFUSED', S.PERMISSION_ERROR)])
def test_dns_rcodes(rcode, status):
    result = DigIntegration('dig').parse('example.com', CommandResult([], 0, f';; ->>HEADER<<- status: {rcode}, id: 1', ''))
    assert result.status == status and result.entities == []


@pytest.mark.parametrize('rtype,value', [('A', '192.0.2.1'), ('AAAA', '2001:db8::1'), ('MX', '10 mail.example.com.'),
                                         ('TXT', '"v=spf1 -all"'), ('CNAME', 'example.net.'),
                                         ('SOA', 'ns.example.com. hostmaster.example.com. 1 2 3 4 5')])
def test_dns_retains_complete_record(rtype, value):
    result = DigIntegration('dig').parse('example.com', CommandResult([], 0, f'example.com. 300 IN {rtype} {value}', ''))
    assert result.status == S.FOUND
    assert result.entities[0].value == value
    assert result.entities[0].metadata['record'] == rtype


def test_dns_bad_record_not_discovery():
    result = DigIntegration('dig').parse('example.com', CommandResult([], 0, 'example.com. 300 IN A 999.1.2.3', ''))
    assert result.status == S.ERROR and not result.entities


def test_harvester_scopes_and_ignores_banner():
    output = 'maintainer@vendor.test\n[*] Emails found: 2\na@example.com\nx@badexample.com\n[*] Hosts found: 2\nsub.example.com:192.0.2.1\nbadexample.com\n'
    result = TheHarvesterIntegration('harvester').parse('example.com', CommandResult([], 0, output, ''))
    assert {e.value for e in result.entities} == {'a@example.com', 'sub.example.com'}
    assert all(e.status == S.UNVERIFIED for e in result.entities)


@pytest.mark.parametrize('output', ['not json', '{}', '[null]', '[{"Error":"invalid file"}]', '[]'])
def test_exif_malformed_response(output):
    result = ExifToolIntegration('exiftool').parse('image.png', CommandResult([], 0, output, ''))
    assert result.status == S.ERROR and not result.entities


def test_no_confidence_inflation_and_no_case_sensitive_url_merge():
    entities = [Entity(EntityType.URL, 'https://example.com/Case', 'a', confidence=.5),
                Entity(EntityType.URL, 'https://EXAMPLE.COM/Case', 'b', confidence=.6),
                Entity(EntityType.URL, 'https://example.com/case', 'a', confidence=.5)]
    merged = normalize_entities(entities)
    assert len(merged) == 2 and merged[0].confidence == .5
    assert normalize_entities(merged)[0].confidence == .5


def test_input_and_suggestions_never_confirmed_or_risk():
    inv = Investigation('email', 'a@example.com')
    inv.entities = [Entity(EntityType.EMAIL, 'a@example.com', 'input', confidence=1, evidence='input', status=S.CONFIRMED)]
    inv.add_suggestion('search', 'https://github.com/search?q=a')
    assert inv.entities[0].status == S.UNVERIFIED
    risk = compute_risk(inv)
    assert risk.exposure_score == 0 and risk.confidence_score == 0


def test_shell_timeout_unicode_large_output_and_permission(tmp_path):
    result = run_command([sys.executable, '-c', "print('రామ', flush=True);import time;time.sleep(2)"], timeout=.2)
    assert result.timed_out and isinstance(result.stdout, str) and 'రామ' in result.stdout
    result = run_command([sys.executable, '-c', "import sys;sys.stdout.buffer.write(b'\\xff' * 100000)"], max_output_bytes=4096)
    assert result.output_limited and not result.ok and len(result.stdout) <= 4096
    executable = tmp_path / 'not_executable'
    executable.write_text('test')
    assert run_command([str(executable)]).returncode == 126
    with pytest.raises(ValueError):
        run_command('echo unsafe')


def test_ctrl_c_kills_child_process_group(tmp_path):
    pidfile = tmp_path / 'pid'
    child_code = "import os,time,pathlib;pathlib.Path(" + repr(str(pidfile)) + ").write_text(str(os.getpid()));time.sleep(60)"
    wrapper = "from utils.shell import run_command;run_command(" + repr([sys.executable, '-c', child_code]) + ",timeout=60)"
    proc = subprocess.Popen([sys.executable, '-c', wrapper], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=Path(__file__).resolve().parents[1])
    try:
        deadline = time.monotonic() + 5
        while not pidfile.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        assert pidfile.exists()
        proc.send_signal(signal.SIGINT)
        proc.communicate(timeout=5)
        with pytest.raises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()


def response(monkeypatch, body=None, status=200, raw=None, headers=None):
    res = Mock(status_code=status, headers=headers or {})
    res.__enter__ = Mock(return_value=res)
    res.__exit__ = Mock(return_value=False)
    res.iter_content.return_value = [raw if raw is not None else json.dumps(body).encode()]
    call = Mock(return_value=res)
    monkeypatch.setattr(requests, 'request', call)
    return call


@pytest.mark.parametrize('code,status', [(401, S.PERMISSION_ERROR), (403, S.PERMISSION_ERROR), (404, S.NOT_FOUND), (429, S.RATE_LIMITED), (500, S.API_ERROR), (503, S.API_ERROR), (302, S.API_ERROR)])
def test_http_error_taxonomy(monkeypatch, code, status):
    response(monkeypatch, status=code)
    with pytest.raises(SourceError) as error:
        request_json('GET', 'https://example.com')
    assert error.value.status == status


@pytest.mark.parametrize('error,status', [(requests.Timeout('secret'), S.TIMEOUT), (requests.ConnectionError('secret'), S.NETWORK_ERROR)])
def test_http_transport_failure_is_sanitized(monkeypatch, error, status):
    monkeypatch.setattr(requests, 'request', Mock(side_effect=error))
    with pytest.raises(SourceError) as caught:
        request_json('GET', 'https://example.com')
    assert caught.value.status == status and 'secret' not in str(caught.value)


def test_http_malformed_and_large_response(monkeypatch):
    response(monkeypatch, raw=b'{')
    with pytest.raises(SourceError):
        request_json('GET', 'https://example.com')
    response(monkeypatch, raw=b'a' * 100)
    with pytest.raises(SourceError):
        request_json('GET', 'https://example.com', max_bytes=10)


@pytest.mark.parametrize('provider', [GroqProvider, GeminiProvider])
def test_missing_cloud_keys(provider):
    instance = provider(None, 'configured-model')
    with pytest.raises(AIProviderError) as caught:
        instance.complete('system', 'user')
    assert caught.value.status == S.TOOL_UNAVAILABLE


@pytest.mark.parametrize('code,status', [(401, S.PERMISSION_ERROR), (403, S.PERMISSION_ERROR), (404, S.API_ERROR), (429, S.RATE_LIMITED), (500, S.API_ERROR)])
def test_invalid_groq_key_or_model_http_errors(monkeypatch, code, status):
    response(monkeypatch, status=code)
    with pytest.raises(AIProviderError) as caught:
        GroqProvider('fake-test-key', 'model').complete('system', 'user')
    assert caught.value.status == status and 'fake-test-key' not in str(caught.value)


@pytest.mark.parametrize('provider', [GroqProvider('fake', 'model'), GeminiProvider('fake', 'model'), OllamaProvider(model='model')])
@pytest.mark.parametrize('body', [None, [], {}, {'choices': [None]}, {'message': {'content': None}}])
def test_malformed_ai_responses(monkeypatch, provider, body):
    monkeypatch.setattr(provider, 'require_model', lambda: None)
    response(monkeypatch, body=body)
    with pytest.raises(AIProviderError):
        provider.complete('system', 'user')


def test_gemini_uses_header_not_url_key(monkeypatch):
    provider = GeminiProvider('fake-secret', 'model')
    monkeypatch.setattr(provider, 'require_model', lambda: None)
    call = response(monkeypatch, {'candidates': [{'content': {'parts': [{'text': 'ok'}]}}]})
    assert provider.complete('s', 'u') == 'ok'
    assert call.call_args.kwargs['headers']['x-goog-api-key'] == 'fake-secret'
    assert 'params' not in call.call_args.kwargs


def test_ai_rejects_fabrication_and_only_renders_evidence(monkeypatch):
    inv = Investigation('domain', 'example.com')
    entity = Entity(EntityType.DNS_RECORD, '192.0.2.1', 'dns', status=S.CONFIRMED, evidence='example.com A 192.0.2.1')
    inv.entities.append(entity)
    engine = AIEngine(AIConfig())
    monkeypatch.setattr(engine.provider, 'is_configured', lambda: True)
    monkeypatch.setattr(engine.provider, 'complete', lambda *a, **k: json.dumps({'executive_evidence_ids': ['fake-person'], 'technical_evidence_ids': [], 'recommendation_ids': []}))
    engine.enrich(inv)
    assert inv.ai_status == S.API_ERROR and inv.ai_summary is None and len(inv.entities) == 1
    monkeypatch.setattr(engine.provider, 'complete', lambda *a, **k: json.dumps({'executive_evidence_ids': [entity.id], 'technical_evidence_ids': [], 'recommendation_ids': ['recheck_dns']}))
    engine.enrich(inv)
    assert entity.evidence in inv.ai_summary and inv.ai_status == S.FOUND and len(inv.entities) == 1
    data = json.loads(_facts_block(inv))
    assert set(data) >= {'verified', 'unverified', 'errors', 'sources'}


def test_config_secrets_redacted_and_literal_yaml_key_ignored(monkeypatch, tmp_path):
    import config.loader
    path = tmp_path / 'config.yaml'
    path.write_text('ai:\n  groq:\n    api_key: literal-secret\n')
    monkeypatch.setattr(config.loader, 'USER_CONFIG_PATH', path)
    assert load_config().ai.groq.api_key is None
    monkeypatch.setenv('GROQ_API_KEY', 'fake-env-secret')
    cfg = load_config()
    assert cfg.ai.groq.api_key.get_secret_value() == 'fake-env-secret'
    assert 'fake-env-secret' not in json.dumps(cfg.model_dump(mode='json'))


@pytest.mark.parametrize('yaml', ['[]', 'general: [', 'general:\n  timeout_seconds: 0', 'ai: bad', 'ai:\n  provider: invalid'])
def test_bad_config_errors_are_controlled(tmp_path, yaml):
    path = tmp_path / 'bad.yaml'
    path.write_text(yaml)
    with pytest.raises(ConfigError):
        load_config(str(path))


def test_registry_alias_and_executable_permissions(tmp_path):
    executable = tmp_path / 'harvester'
    executable.write_text('#!/bin/sh\nexit 0\n')
    executable.chmod(0o700)
    registry = ToolRegistry({'theharvester': str(executable), 'whois': '/missing/tool'})
    assert registry.is_available('theHarvester')
    assert dict(registry.summary_table_rows())['whois'] == 'FAILED'
    assert 'NOT REQUIRED' in dict(registry.summary_table_rows())['masscan']


@pytest.mark.parametrize('args', [[], ['--help'], ['version'], ['investigate', '--help'], ['update-tools']])
def test_cli_starts(args):
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize('args', [['--invalid'], ['investigate'], ['investigate', '--domain', 'bad;input'], ['investigate', '--username', '--help'],
                                  ['investigate', '--email', 'a..b@example.com'], ['investigate', '--ip', '999.1.2.3'],
                                  ['investigate', '--domain', ''], ['investigate', '--phone', '------'],
                                  ['investigate', '--company', ''], ['investigate', '--domain', 'example.com', '--formats', 'bogus']])
def test_cli_invalid_arguments(args, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, args)
    assert result.exit_code != 0
    assert 'Traceback' not in result.output


@pytest.mark.parametrize('flag,target', [('--domain', 'example.com'), ('--ip', '192.0.2.1'), ('--username', 'alice'), ('--email', 'alice@example.com'), ('--name', 'రామ అంజనేయులు'), ('--company', 'Example & Sons')])
def test_cli_offline_all_targets(flag, target, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ['investigate', flag, target, '--offline', '--formats', 'json,markdown,html,csv'])
    assert result.exit_code == 0, result.output
    data = json.loads(next((tmp_path / 'exports').glob('*.json')).read_text())
    assert data['completed_at'] and data['ai_status'] == 'NOT REQUIRED'
    assert all(r['status'] in [s.value for s in S] for r in data['tool_results'])
    assert '\x1b[' not in result.output


def test_cli_ctrl_c_handled(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Orchestrator, 'investigate', Mock(side_effect=KeyboardInterrupt))
    result = CliRunner().invoke(app, ['investigate', '--domain', 'example.com', '--no-ai'])
    assert result.exit_code == 130 and 'Traceback' not in result.output


def test_invalid_ollama_config_does_not_lose_collection():
    config = AppConfig(ai={'ollama': {'host': 'http://['}})
    inv = Orchestrator(config).investigate('person', 'Jane Doe')
    assert inv.suggestions and inv.completed_at and inv.ai_status == S.API_ERROR


def test_offline_api_also_disables_ai(monkeypatch):
    call = Mock()
    monkeypatch.setattr('core.orchestrator.AIEngine', call)
    inv = Orchestrator(AppConfig()).investigate('person', 'Jane Doe', offline=True)
    call.assert_not_called()
    assert inv.ai_status == S.NOT_REQUIRED


def test_model_availability_not_guessed(monkeypatch):
    provider = GroqProvider('fake-key', 'retired-model')
    response(monkeypatch, {'data': [{'id': 'available-model', 'active': True}]})
    with pytest.raises(AIProviderError, match='unavailable'):
        provider.complete('s', 'u')


def test_logs_redact_keys_and_do_not_raise_on_missing_directory(monkeypatch, tmp_path):
    from utils.logger import setup_logging, get_logger
    secret = 'test-secret-value-never-log'
    monkeypatch.setenv('GROQ_API_KEY', secret)
    logger = setup_logging(str(tmp_path / 'logs'))
    get_logger('module').warning('request failed with key %s', secret)
    for handler in logger.handlers:
        handler.flush()
    for file in (tmp_path / 'logs').iterdir():
        assert secret not in file.read_text()
        assert '[REDACTED]' in file.read_text()
    blocker = tmp_path / 'blocker'
    blocker.write_text('file')
    setup_logging(str(blocker / 'logs'))


def test_http_total_deadline_on_small_chunks(monkeypatch):
    import utils.http
    call = response(monkeypatch, raw=b'{}')
    ticks = iter([0, 10])
    monkeypatch.setattr(utils.http.time, 'monotonic', lambda: next(ticks))
    with pytest.raises(SourceError) as error:
        request_json('GET', 'https://example.com', timeout=1)
    assert error.value.status == S.TIMEOUT


def test_empty_success_remains_unknown():
    for wrapper in (WhoisIntegration, SherlockIntegration, DigIntegration, TheHarvesterIntegration, NmapIntegration):
        target = 'alice' if wrapper is SherlockIntegration else 'example.com'
        result = wrapper('tool').parse(target, CommandResult([], 0, '', ''))
        assert result.status == S.UNKNOWN and not result.entities
