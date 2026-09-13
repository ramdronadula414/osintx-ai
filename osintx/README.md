# OSINT-X AI

**AI-Powered Linux OSINT Investigation Framework**

OSINT-X AI is a professional, command-line-only OSINT automation framework
for Linux. It orchestrates well-known public-source OSINT tools (Sherlock,
theHarvester, whois, dig, nmap, ExifTool, and Tesseract), normalizes their
output into a single schema, prioritizes existing evidence with an AI backend (Gemini,
Groq, or a locally running Ollama model), and generates professional,
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
- Deterministic inventory/exposure metrics based on confirmed observations only; these are not vulnerability or identity probabilities.
- Optional Gemini / Groq / Ollama evidence prioritization. Models return existing evidence IDs and predefined action IDs; all summaries are rendered from collected evidence. Free-form model claims are rejected.
- Reports in Markdown, JSON, CSV, HTML, DOCX, and PDF.
- Plugin system to add new tools/data sources without touching the core.
- Local SQLite investigation history.
- Structured logging (text + JSON lines) for audit trails.

## Quick Start

```bash
git clone https://github.com/ramdronadula414/osintx-ai.git
cd osintx-ai/osintx
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .          # installs the `osintx` command

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

Set `ai.provider` in `~/.osintx/config.yaml`, or use `OSINTX_AI_PROVIDER`.
API keys are read **only from environment variables**, and are redacted from `config --show`.
Cloud model names must be configured explicitly after checking available models:

```bash
export GEMINI_API_KEY="..."
export GROQ_API_KEY="..."
# Or run Ollama locally for local AI processing (collection can still use the network):
# Run `ollama serve` in another terminal, then:
ollama pull llama3.1
```

```bash
export OSINTX_AI_PROVIDER=groq
osintx models --provider groq
export GROQ_MODEL="<a chat model returned by the provider>"
# Gemini: GEMINI_API_KEY (or GOOGLE_API_KEY), GEMINI_MODEL
# Run `osintx models --provider gemini` to inspect the current catalogue.
```

An unavailable key, model, API, or Ollama server leaves collection results intact.
There is no automatic fallback to a different cloud provider.

## Evidence and status semantics

- **CONFIRMED / FOUND:** a directly obtained, parsed source observation. This confirms what the source returned, not a person's identity, account ownership, metadata authenticity, or a vulnerability.
- **UNVERIFIED:** Sherlock/theHarvester candidates, historical certificate names, company-name matches, OCR/barcode text, or other findings without independent confirmation.
- **NOT FOUND:** the particular source explicitly returned no match/record. This is never a claim of global nonexistence.
- **UNKNOWN:** insufficient evidence or an empty/unrecognized successful command response.
- **TOOL UNAVAILABLE, API ERROR, NETWORK ERROR, PERMISSION ERROR, RATE LIMITED, TIMEOUT, ERROR:** collection failure categories; failed/partial command output is never promoted into entities.
- **NOT REQUIRED:** deliberately skipped work, such as offline network collection or an unauthorized scan.

Search suggestions have a separate list in every report and do not contribute to findings, scores, or AI evidence. Confidence defaults to `null` (unassessed) with a written evidence basis. Repeated findings never increase confidence automatically. Old history reports without statuses remain legacy/unverified.

## Supported coverage and fallback behavior

| Target | Collection | Limitations |
|---|---|---|
| Person | Encoded public search suggestions | No automatic person/identity discovery |
| Username | Sherlock candidates; Maigret diagnostics | No generic HTTP response is confirmation; candidate ownership remains unverified |
| Email | Domain MX/TXT/DMARC and WHOIS | Syntax does not verify mailbox, accounts, or breaches |
| Domain | DNS, WHOIS, passive theHarvester, crt.sh plugin | Certificate names can be historical or wildcard-only |
| IP | Public WHOIS and PTR; explicit-authorized Nmap | Non-global IP public lookups skipped; no automatic active scanning |
| Company | Candidate GitHub organization repositories; search suggestions | Name-derived affiliation unverified; first 30 repositories only |
| Image | EXIF, OCR, QR/barcode, SHA-256 | Metadata can be edited; no face identification; no automatic image uploads |

DNS uses dnspython when `dig` is missing. Image EXIF uses Pillow when ExifTool is missing (top-level EXIF only). Optional report and QR dependencies:

```bash
python -m pip install -e ".[reports]"  # DOCX/PDF
python -m pip install -e ".[qr]"       # pyzbar; Linux also needs libzbar0
osintx investigate --domain example.com --offline --no-ai
```

`--offline` skips all network collection and AI; local image processing and generated search suggestions remain available. It does not claim that a lookup was performed. `update-tools` distinguishes executable detection from implemented integrations. Amass, subfinder, dnsrecon, httpx, masscan, and other detection-only binaries are not automatically run.

Python 3.10+ is the compatibility target. See [verification](docs/VERIFICATION.md) for runtimes and services actually tested, and [troubleshooting](docs/INSTALL.md#troubleshooting) for setup failures.

## Testing

```bash
python -m pip install -e ".[dev,reports,qr]"
python -m pytest -v
```

## License

MIT — see [LICENSE](LICENSE).
