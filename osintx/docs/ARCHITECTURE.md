# Architecture

```
osintx/
├── osintx.py          # entry point (delegates to cli.app)
├── cli.py             # Typer CLI: commands, argument parsing, output rendering
├── config/
│   ├── config.yaml     # default configuration template
│   └── loader.py        # pydantic-validated config loader, env var expansion
├── core/
│   ├── schema.py        # unified data model: Entity, ToolResult, Investigation, RiskAssessment
│   ├── tool_registry.py # detects which Linux OSINT tools are installed
│   └── orchestrator.py  # ties module -> normalization -> timeline -> risk -> AI together
├── engines/
│   ├── normalization.py   # dedupe/merge entities across tools
│   ├── timeline.py        # builds chronological event list
│   ├── risk.py            # rule-based (non-AI) scoring
│   └── entity_extraction.py  # regex-based extraction from free text
├── ai/
│   ├── provider.py         # abstract AIProvider interface
│   ├── providers/           # gemini.py, groq.py, ollama.py implementations
│   └── engine.py            # prompts, anti-hallucination system prompt, enrichment
├── modules/                # one file per investigation target type
│   ├── person_module.py, username_module.py, email_module.py
│   ├── domain_module.py, ip_module.py, company_module.py, image_module.py
├── integrations/            # safe subprocess wrappers per external tool
│   ├── base.py               # ToolIntegration ABC (build_argv/parse/run)
│   ├── whois_tool.py, dig_tool.py, sherlock_tool.py, theharvester_tool.py,
│   │   nmap_tool.py, exiftool_tool.py
│   └── registry.py            # name -> wrapper class lookup
├── plugins/
│   ├── base.py                # OsintxPlugin ABC + discover_plugins()
│   └── installed/               # drop-in plugin files (e.g. crtsh_plugin.py)
├── reports/
│   ├── markdown_report.py, html_report.py, data_report.py (JSON/CSV),
│   │   docx_report.py, pdf_report.py
│   └── generator.py            # dispatches to every configured format
├── database/
│   └── store.py                 # SQLite investigation history
├── utils/
│   ├── shell.py                  # safe subprocess execution (no shell=True, timeouts)
│   ├── validators.py             # per-target-type input validation
│   └── logger.py                  # rich console + text + JSON-lines logging
└── tests/                        # pytest unit + integration tests (mocked tool execution)
```

## Data flow for `osintx investigate --domain example.com`

1. `cli.py` parses flags, loads config, builds an `Orchestrator`.
2. `Orchestrator.investigate()` picks `DomainModule` from `MODULE_MAP`.
3. `DomainModule.run()` checks `ToolRegistry` for whois/dig/theHarvester
   availability, and for each available tool, gets a wrapper from
   `integrations.registry.get_integration()`, calls `.run(target)`, and
   appends the resulting `ToolResult` (with parsed `Entity` objects) to the
   `Investigation`. It also invokes any plugin that declares support for
   `"domain"` targets (e.g. the bundled crt.sh plugin).
4. Back in the orchestrator: `engines.normalization.normalize_entities()`
   dedupes/merges entities; `engines.timeline.build_timeline()` builds a
   chronological view; `engines.risk.compute_risk()` computes rule-based
   scores.
5. If AI is enabled, `ai.engine.AIEngine.enrich()` sends a structured evidence envelope. The provider returns only existing evidence IDs and predefined action IDs. The engine validates these and renders executive/technical sections from source evidence. Model prose is discarded; a prompt is not the enforcement boundary.
6. `database.store.save_investigation()` persists the full investigation
   to SQLite.
7. `reports.generator.generate_reports()` writes every configured format
   to the output directory, with each report layout keeping AI-generated
   sections visually/structurally distinct from raw collected facts.

## Design principles

- **Safety first**: every subprocess call goes through
  `utils.shell.run_command`, which never uses `shell=True`, so no user
  input can be interpreted as shell syntax. Every target string is
  validated by `utils.validators` before it reaches a subprocess, DNS
  query, or HTTP request.
- **Graceful degradation**: a missing tool produces a warning and a
  skipped step, never a crash.
- **Auditable scoring**: risk/exposure scores are deterministic, rule-based
  code, not LLM output, so an analyst can verify exactly how a number was
  derived.
- **AI is a summarizer, not a source**: the AI engine only ever receives
  facts already collected by modules/tools; its system prompt explicitly
  forbids introducing new claims not present in that input.

## Reliability and evidence boundaries (1.1)

- Orchestrator validates/normalizes the target before invoking any module; validation errors are not swallowed.
- `ResultStatus` distinguishes evidence, absence, unknowns, errors, and deliberate skips. Failed `ToolResult` objects cannot contribute entities, even if a plugin supplies them.
- `utils.shell` uses argv lists, process groups, a deadline, output caps, UTF-8 replacement decoding, and Ctrl+C cleanup. It never executes through a shell.
- `utils.http` classifies API/network failures, rejects redirects/malformed JSON, caps bytes, and checks total elapsed time between bounded reads.
- `modules.base` records missing tools and provides DNS fallback. Offline mode skips network steps explicitly.
- `integrations/dns_python.py` uses bounded resolver lifetimes; `dig` parses complete typed DNS records. Source observations are not identity or ownership claims.
- All report generators use the same evidence grouping semantics. Optional binary formats are imported lazily; failure of one format does not block others. Reports are written through temporary files to avoid claiming partial outputs succeeded.
- `config/config.yaml` and bundled plugin sources are included in installed wheels. Core dependencies come from one requirements file.

External drop-in Python plugins remain trusted local code. Their authors must honor timeout/resource bounds; discovery/runner errors are recorded but arbitrary plugin code is not sandboxed by the orchestrator.
