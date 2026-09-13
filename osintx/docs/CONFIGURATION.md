# Configuration Guide

Configuration overlays shipped `config/config.yaml` with `~/.osintx/config.yaml`. The Python loader also accepts an explicit extra path; the CLI does not currently expose `--config`.

`osintx config --init` creates a user configuration; `osintx config --show` prints resolved values with API keys masked. Missing/malformed files and invalid data types receive concise errors.

| Setting | Behavior |
|---|---|
| `general.output_dir` | Default report output directory; CLI `--output-dir` overrides it |
| `general.log_dir`, `log_level` | Redacted logs; console logging continues if files cannot be written |
| `general.timeout_seconds` | Per-tool/query time budget, 1–300 seconds; whole investigations can run multiple steps |
| `general.threads`, `cache_dir`, `proxy` | Reserved; no parallel scheduler/cache/custom-proxy behavior is implemented |
| `ai.provider` | `gemini`, `groq`, `ollama`; `OSINTX_AI_PROVIDER` overrides |
| `ai.timeout_seconds` | AI HTTP request budget, 1–300 seconds |
| `ai.gemini.model`, `ai.groq.model` | Explicit model IDs; `GEMINI_MODEL` / `GROQ_MODEL` override |
| `ai.gemini.api_key`, `ai.groq.api_key` | Environment only; literal YAML credentials ignored |
| `ai.ollama.host`, `ai.ollama.model` | Ollama API host and installed model name |
| `tools` | Optional executable paths; `null` means PATH detection |
| `reports.formats` | A nonempty subset of `markdown,json,csv,html,docx,pdf` |
| `reports.include_raw_tool_output` | Include bounded diagnostic stdout in stored/exported JSON; false removes it before persistence |
| `security.allow_port_scanning`, `rate_limit_per_host_seconds` | Legacy reserved settings; do not enable scanning or promise throttling |

For HTTP proxies, use standard `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` environment variables. DNS and external tools manage their own network behavior. OSINT-X performs no automatic HTTP retries and never switches AI providers automatically.

Keys are read from `GROQ_API_KEY` and `GEMINI_API_KEY` (fallback `GOOGLE_API_KEY`). Model availability is checked against provider catalogues at runtime; `osintx models --provider ...` displays them. Groq's catalogue can include non-chat models, so choose a chat-compatible model. Unknown response shapes and unavailable models are reported as API errors.

Cloud AI receives at most 100 confirmed and 100 unverified observations, with a 150,000-byte evidence budget. Larger evidence sets still remain in local reports. Free-form model text cannot be promoted to discoveries: the model must return valid evidence/action IDs.
