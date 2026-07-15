# Configuration Guide

OSINT-X AI loads configuration in this order (later overrides earlier):

1. `config/config.yaml` (shipped defaults)
2. `~/.osintx/config.yaml` (per-user overrides — created by `osintx config --init`)
3. `--config <path>` if a command supports it

## Sections

### `general`
| Key | Description |
|---|---|
| `output_dir` | Where reports are written by default |
| `cache_dir` | Scratch space for cached tool output |
| `log_dir` | Location of `osintx.log` / `osintx.jsonl` |
| `log_level` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `threads` | Reserved for future parallel tool execution |
| `timeout_seconds` | Per-tool subprocess timeout |
| `proxy` | Optional SOCKS/HTTP proxy for outbound requests |

### `ai`
| Key | Description |
|---|---|
| `provider` | `gemini`, `groq`, or `ollama` |
| `gemini.api_key` / `groq.api_key` | Reference env vars like `${GEMINI_API_KEY}` |
| `ollama.host` / `ollama.model` | Local Ollama server + model name |

### `tools`
Optional explicit paths per tool name, e.g.:

```yaml
tools:
  sherlock: /opt/sherlock/sherlock.py
```

Leave `null` for auto-detection via `PATH`.

### `reports`
| Key | Description |
|---|---|
| `formats` | Default formats generated when `--formats` isn't passed |
| `include_raw_tool_output` | Whether raw stdout is embedded in JSON reports |

### `security`
| Key | Description |
|---|---|
| `allow_port_scanning` | Config-level default; the CLI still requires `--i-have-authorization` per run |
| `rate_limit_per_host_seconds` | Minimum delay between requests to the same host |

## Environment variables

Any config value written as `${VAR_NAME}` is resolved from the process
environment at load time:

```bash
export GEMINI_API_KEY="sk-..."
export GROQ_API_KEY="gsk-..."
```
