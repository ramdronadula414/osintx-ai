# OSINT-X AI

**AI-Powered Linux OSINT Investigation Framework**

OSINT-X AI is a professional, command-line-only OSINT automation framework
for Linux. It orchestrates well-known public-source OSINT tools (Sherlock,
theHarvester, whois, dig, nmap, ExifTool, and more), normalizes their
output into a single schema, correlates it with an AI backend (Gemini,
Groq, or a fully offline Ollama model), and generates professional,
multi-format investigation reports.

> **Scope & ethics.** OSINT-X AI only automates workflows an analyst could
> run manually with public tools against public data. It never bypasses
> authentication, scrapes private/logged-in content, or performs
> unauthorized scanning. Port scanning (nmap) requires an explicit
> `--i-have-authorization` flag. Read [docs/ETHICS.md](docs/ETHICS.md).

---

## Features

- Pure Linux terminal UX (Rich tables, progress spinners, colored output) — no GUI, no web server.
- Auto-detects installed OSINT tools and skips missing ones gracefully.
- Modules for person, username, email, domain, IP, company, and image investigations.
- Unified entity schema + deduplication/normalization across tools.
- Rule-based (non-AI) risk & exposure scoring, fully auditable.
- AI engine (Gemini / Groq / Ollama) for executive & technical summaries, correlation, and follow-up recommendations — clearly separated from raw collected facts in every report.
- Reports in Markdown, JSON, CSV, HTML, DOCX, and PDF.
- Plugin system to add new tools/data sources without touching the core.
- Local SQLite investigation history.
- Structured logging (text + JSON lines) for audit trails.

## Quick Start

```bash
git clone <this-repo> osintx && cd osintx
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .          # installs the `osintx` command

osintx config --init
osintx update-tools        # see which OSINT tools are detected on your system
osintx investigate --domain example.com
```

See [docs/INSTALL.md](docs/INSTALL.md) for installing the underlying Linux
OSINT tools (Sherlock, theHarvester, Amass, etc.) on Kali/Ubuntu/Debian.

## Example Commands

```bash
osintx investigate --name "John Doe"
osintx investigate --username johndoe
osintx investigate --email john@example.com
osintx investigate --domain example.com
osintx investigate --ip 8.8.8.8 --i-have-authorization
osintx investigate --company OpenAI
osintx investigate --image ./photo.jpg
osintx investigate --domain example.com --formats markdown,pdf,docx --output-dir ./exports
osintx report latest
osintx history
osintx config --show
osintx update-tools
osintx version
```

## Project Structure

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a full breakdown of
`core/`, `engines/`, `ai/`, `modules/`, `integrations/`, `plugins/`, and
`reports/`.

## Configuring the AI Provider

Edit `~/.osintx/config.yaml` (created by `osintx config --init`) or set
environment variables referenced in it:

```bash
export GEMINI_API_KEY="..."
export GROQ_API_KEY="..."
# or run Ollama locally for a fully offline setup:
ollama serve && ollama pull llama3.1
```

## Testing

```bash
pip install -r requirements.txt
pytest -v
```

## License

MIT — see [LICENSE](LICENSE).
