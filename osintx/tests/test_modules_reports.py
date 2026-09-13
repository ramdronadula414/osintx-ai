import json
from pathlib import Path
from unittest.mock import Mock

import dns.resolver
import dns.exception
import pytest
from PIL import Image
from typer.testing import CliRunner
from core.schema import Entity, EntityType, Investigation, ToolResult, ResultStatus as S
from core.orchestrator import Orchestrator
from config.loader import AppConfig
from modules.domain_module import DomainModule
from modules.company_module import CompanyModule
from modules.image_module import ImageModule
from modules.ip_module import IPModule
from plugins.installed.crtsh_plugin import CrtShPlugin
from reports.generator import generate_reports
from reports.data_report import generate_csv
from utils.http import SourceError
from cli import app


class MissingRegistry:
    def is_available(self, name):
        return False
    def path_for(self, name):
        return None


def test_domain_missing_tools_uses_dns_fallback_and_records_network_error(monkeypatch):
    resolver = Mock()
    resolver.resolve.side_effect = dns.exception.Timeout
    monkeypatch.setattr(dns.resolver, 'Resolver', Mock(return_value=resolver))
    inv = Investigation('domain', 'example.com')
    DomainModule(MissingRegistry(), timeout=1).run('example.com', inv)
    assert inv.entities == []
    assert sum(r.status == S.TIMEOUT for r in inv.tool_results) == 7
    assert any(r.tool == 'crt.sh' and r.status == S.NETWORK_ERROR for r in inv.tool_results)
    assert any(r.tool == 'whois' and r.status == S.TOOL_UNAVAILABLE for r in inv.tool_results)


def test_dns_fallback_confirmed_record(monkeypatch):
    from integrations.dns_python import lookup
    answer = Mock()
    answer.canonical_name = 'example.com.'
    answer.__iter__ = Mock(return_value=iter([Mock(to_text=lambda: '192.0.2.1')]))
    resolver = Mock()
    resolver.resolve.return_value = answer
    monkeypatch.setattr(dns.resolver, 'Resolver', Mock(return_value=resolver))
    result = lookup('example.com', 'A', timeout=2)
    assert result.status == S.FOUND and result.entities[0].status == S.CONFIRMED
    assert resolver.resolve.call_args.kwargs['lifetime'] == 2


def test_company_candidate_never_proves_ownership(monkeypatch):
    monkeypatch.setattr('modules.company_module.request_json', lambda *a, **k: [{'html_url': 'https://github.com/example/repo', 'owner': {'login': 'example'}, 'language': 'Python', 'stargazers_count': 3}])
    inv = Investigation('company', 'Example')
    CompanyModule(MissingRegistry()).run('Example', inv)
    assert len(inv.entities) == 1 and inv.entities[0].status == S.UNVERIFIED
    assert inv.entities[0].metadata['stars'] == 3
    assert len(inv.suggestions) == 2


@pytest.mark.parametrize('payload', [None, {}, [None], [{'owner': None}], [{'html_url': 'https://github.com/example/repo', 'owner': {'login': None}}]])
def test_company_bad_api_response(payload, monkeypatch):
    monkeypatch.setattr('modules.company_module.request_json', lambda *a, **k: payload)
    inv = Investigation('company', 'Example')
    CompanyModule(MissingRegistry()).run('Example', inv)
    assert not inv.entities and inv.tool_results[0].status == S.API_ERROR
    assert inv.suggestions


def test_company_rate_limit_keeps_search_suggestions(monkeypatch):
    monkeypatch.setattr('modules.company_module.request_json', Mock(side_effect=SourceError(S.RATE_LIMITED, 'HTTP 429')))
    inv = Investigation('company', 'Example')
    CompanyModule(MissingRegistry()).run('Example', inv)
    assert inv.tool_results[0].status == S.RATE_LIMITED and inv.suggestions


def test_crtsh_boundary_wildcards_and_duplicates(monkeypatch):
    monkeypatch.setattr('plugins.installed.crtsh_plugin.request_json', lambda *a, **k: [{'id': 1, 'name_value': '*.example.com\nsub.example.com\nbadexample.com\nsub.example.com\nbad;example.com'}])
    result = CrtShPlugin().run('example.com', 'domain')
    assert {e.value for e in result.entities} == {'*.example.com', 'sub.example.com'}
    assert all(e.status == S.UNVERIFIED for e in result.entities)


@pytest.mark.parametrize('payload', [{}, [None], [{'name_value': None}]])
def test_crtsh_malformed_response(payload, monkeypatch):
    monkeypatch.setattr('plugins.installed.crtsh_plugin.request_json', lambda *a, **k: payload)
    assert CrtShPlugin().run('example.com', 'domain').status == S.API_ERROR


def test_image_fallback_hash_metadata_and_bad_file(tmp_path):
    file = tmp_path / 'photo.jpg'
    exif = Image.Exif()
    exif[271] = 'Test camera'
    Image.new('RGB', (16, 16), 'red').save(file, exif=exif)
    inv = Investigation('image', str(file))
    ImageModule(MissingRegistry(), offline=True).run(str(file), inv)
    assert any(e.type == EntityType.FILE_HASH and len(e.value) == 64 for e in inv.entities)
    assert any(e.source == 'Pillow' and 'Test camera' in e.value for e in inv.entities)
    assert any(r.tool == 'exiftool' and r.status == S.TOOL_UNAVAILABLE for r in inv.tool_results)
    bad = tmp_path / 'bad.jpg'
    bad.write_text('not an image')
    inv = Investigation('image', str(bad))
    ImageModule(MissingRegistry()).run(str(bad), inv)
    assert inv.tool_results[0].status == S.ERROR and not inv.entities


def test_no_nmap_without_authorization(monkeypatch):
    calls = []
    module = IPModule(MissingRegistry())
    monkeypatch.setattr(module, 'run_tool', lambda name, *a, **k: calls.append(name))
    inv = Investigation('ip', '192.0.2.1')
    module.run('192.0.2.1', inv)
    assert 'nmap' not in calls
    assert any(r.tool == 'nmap' and r.status == S.NOT_REQUIRED for r in inv.tool_results)
    module.run('192.0.2.1', inv, allow_port_scan=True)
    assert calls == ['nmap']  # Mock only: no active scan runs in the test suite.


def report_fixture():
    inv = Investigation('company', 'Example < & > Company')
    inv.entities = [Entity(EntityType.DNS_RECORD, '192.0.2.1', 'DNS', status=S.CONFIRMED, evidence='example.com A 192.0.2.1'),
                    Entity(EntityType.TEXT, '=1+1', 'OCR', evidence='OCR text: <script>alert(1)</script>')]
    inv.add_tool_result(ToolResult('tool', 'target', False, status=S.RATE_LIMITED, error='HTTP 429'))
    inv.add_suggestion('Manual search', 'https://example.com/?q=test')
    return inv


def test_all_six_reports_generated_and_distinguish_statuses(tmp_path):
    inv = report_fixture()
    outputs = generate_reports(inv, str(tmp_path), ['markdown', 'json', 'html', 'csv', 'docx', 'pdf'])
    assert len(outputs) == 6, inv.warnings
    for fmt in ('markdown', 'json', 'html', 'csv'):
        text = Path(outputs[fmt]).read_text()
        assert 'CONFIRMED' in text and 'UNVERIFIED' in text and 'RATE LIMITED' in text
    html = Path(outputs['html']).read_text()
    assert '<script>' not in html and '&lt;script&gt;' in html
    from docx import Document
    text = '\n'.join(p.text for p in Document(outputs['docx']).paragraphs)
    assert 'CONFIRMED' in text and 'UNVERIFIED' in text and 'RATE LIMITED' in text
    assert Path(outputs['pdf']).read_bytes().startswith(b'%PDF')
    assert "'=1+1" in generate_csv(inv)


def test_report_optional_dependency_failure_preserves_json(monkeypatch, tmp_path):
    import reports.generator
    original = reports.generator.importlib.import_module
    def imports(name):
        if name == 'reports.pdf_report':
            raise ImportError('reportlab missing')
        return original(name)
    monkeypatch.setattr(reports.generator.importlib, 'import_module', imports)
    inv = report_fixture()
    written = generate_reports(inv, str(tmp_path), ['pdf', 'json'])
    assert set(written) == {'json'}
    assert any('pdf report failed' in w for w in json.loads(Path(written['json']).read_text())['warnings'])


def test_output_filesystem_failure_still_prints_results(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / 'file'
    path.write_text('not a directory')
    result = CliRunner().invoke(app, ['investigate', '--name', 'Jane Doe', '--offline', '--output-dir', str(path)])
    assert result.exit_code == 1 and 'SEARCH SUGGESTIONS' in result.output and 'No reports written' in result.output
    assert 'Traceback' not in result.output


def test_history_write_failure_does_not_prevent_reports(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('cli.save_investigation', Mock(side_effect=PermissionError('denied')))
    result = CliRunner().invoke(app, ['investigate', '--name', 'Jane Doe', '--offline', '--formats', 'json'])
    assert result.exit_code == 0 and 'History could not be saved' in result.output
    assert list((tmp_path / 'exports').glob('*.json'))


def test_raw_output_config_respected(monkeypatch):
    def collect(self, target, inv, **kwargs):
        inv.add_tool_result(ToolResult('tool', target, True, raw_output='diagnostic'))
    monkeypatch.setattr('modules.person_module.PersonModule.run', collect)
    config = AppConfig()
    config.reports.include_raw_tool_output = False
    inv = Orchestrator(config).investigate('person', 'Jane Doe', use_ai=False)
    assert inv.tool_results[0].raw_output == ''


def test_history_roundtrip_and_corrupt_row(tmp_path, monkeypatch):
    import database.store
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ['investigate', '--name', 'Jane Doe', '--offline', '--formats', 'json'])
    assert result.exit_code == 0
    assert CliRunner().invoke(app, ['history']).exit_code == 0
    assert CliRunner().invoke(app, ['report', 'latest']).exit_code == 0
    import sqlite3
    with sqlite3.connect(database.store.DB_PATH) as conn:
        conn.execute("UPDATE investigations SET data_json = 'not json'")
    result = CliRunner().invoke(app, ['report', 'latest'])
    assert result.exit_code == 1 and 'Traceback' not in result.output


def test_terminal_source_controls_do_not_execute(capsys):
    from cli import _print_summary
    inv = Investigation('person', 'Jane Doe')
    inv.entities = [Entity(EntityType.TEXT, 'source\x1b[2J', 'test')]
    _print_summary(inv)
    assert '\x1b' not in capsys.readouterr().out
