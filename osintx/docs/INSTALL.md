# Installation Guide

## Python application

Use Python 3.10+ on Linux. Create a virtual environment to avoid Debian/Kali system-Python package restrictions.

```bash
git clone https://github.com/ramdronadula414/osintx-ai.git
cd osintx-ai/osintx
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .
osintx --help
osintx version
```

`requirements.txt` is the single source of core Python dependencies, also used by `pyproject.toml`. System OSINT binaries are not pip dependencies.

Optional features:

```bash
python -m pip install -e ".[reports]"  # PDF and DOCX
python -m pip install -e ".[qr]"       # barcode decoding (requires libzbar0 below)
python -m pip install -e ".[dev,reports,qr]"
python -m pytest -q
```

## Optional Linux tools

Install only the tools you need; missing tools are recorded and do not stop the investigation. For Debian-family distributions:

```bash
sudo apt update
sudo apt install whois dnsutils nmap libimage-exiftool-perl tesseract-ocr libzbar0 fonts-dejavu-core
```

Sherlock and theHarvester are separate applications. Install them using their official instructions or Kali packages, then verify their own `--help` and `osintx update-tools`. Prefer `pipx` for separate Python CLI tools rather than mixing their dependencies into OSINT-X's environment.

- Sherlock: https://sherlockproject.xyz/installation
- theHarvester: https://github.com/laramies/theHarvester
- ExifTool: https://exiftool.org/

Detection-only entries such as amass, subfinder, httpx, dnsrecon, masscan and yt-dlp do not have collection wrappers in this release. A found executable is not a guarantee of compatible version or successful execution. Configure explicit executable paths under `tools` when necessary. The `theHarvester` and legacy lowercase `theharvester` keys are both accepted.

## AI configuration

```bash
osintx config --init
export OSINTX_AI_PROVIDER=groq
export GROQ_API_KEY="<your key>"
osintx models --provider groq
export GROQ_MODEL="<an available chat model ID>"
```

For Gemini, use `GEMINI_API_KEY` or `GOOGLE_API_KEY` and `GEMINI_MODEL`. For local Ollama, start the server, pull a model, and configure `ai.ollama.model`; `osintx models --provider ollama` lists installed names. Availability depends on your account/server. No paid generation is performed by the model-list command.

Never commit keys. Literal YAML API keys are ignored; use the environment. `--no-ai` skips AI; `--offline` also skips all network collection.

## Troubleshooting

| Symptom | Action |
|---|---|
| `externally-managed-environment` | Use the virtual environment; do not modify the system Python |
| Missing import / command | Activate the environment and run `python -m pip install -e .` from `osintx-ai/osintx` |
| `TOOL UNAVAILABLE` | Install that optional executable or use available fallback modules |
| Tool status `FAILED` | Check the configured path is a regular executable and has execute permission |
| AI `PERMISSION ERROR` | Check environment key and provider/account permissions; 401/403 are not missing findings |
| AI model unavailable | List models, select a supported chat/generation model, update model configuration |
| `RATE LIMITED` | Wait for the source limit to reset; the app does not retry automatically |
| `NETWORK ERROR` / `TIMEOUT` | Check network/DNS/proxy; use `--offline` for local processing |
| Empty response `UNKNOWN` | Source output was insufficient; do not interpret it as absence |
| Report write error | Choose a writable `--output-dir`; results remain printed in the terminal |
| PDF/DOCX unavailable | Install `.[reports]`; JSON/Markdown/HTML/CSV continue independently |
| QR unavailable | Install `.[qr]` and `libzbar0`; EXIF/OCR/hash can still run |
| Non-Latin glyphs missing in PDF | Prefer HTML/DOCX/JSON for scripts unsupported by the installed PDF font |

Subprocesses have a configurable time budget and a 1 MiB combined stdout/stderr cap. Exceeding either discards findings from that command. HTTP JSON bodies are capped at 2 MiB. Images are capped at 100 MiB and Pillow's decompression-bomb checks apply. These limits favor controlled failure over unbounded resource use.

No active scan is run without `--i-have-authorization` on that invocation, even if the old reserved configuration flag is set.
