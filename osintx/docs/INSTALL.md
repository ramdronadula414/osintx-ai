# Installation Guide

## 1. Requirements

- Kali Linux 2025+, Ubuntu 24.04+, or another Debian-based distribution
- Python 3.11+
- `pip`, `git`

## 2. Install OSINT-X AI

```bash
git clone <this-repo> osintx
cd osintx
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Verify:

```bash
osintx version
```

## 3. Install underlying Linux OSINT tools (optional but recommended)

OSINT-X AI auto-detects each tool via `PATH` and skips anything not
installed — you don't need all of these to get started, but coverage
improves as you add more.

### Kali Linux
Most tools ship in Kali's repositories already:

```bash
sudo apt update
sudo apt install -y whois dnsutils nmap exiftool tesseract-ocr \
    theharvester amass whatweb git
```

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y whois dnsutils nmap libimage-exiftool-perl \
    tesseract-ocr git
```

### Python/pip-based tools

```bash
pip install sherlock-project socialscan
```

### Go-based tools (subfinder, assetfinder, httpx, katana, naabu, dnsx, waybackurls, gau)

Requires Go 1.21+:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

### Maigret, TruffleHog, SpiderFoot, Photon, Findomain, dnsrecon

```bash
pip install maigret
pip install trufflehog3   # or the official trufflehog release binary
git clone https://github.com/smicallef/spiderfoot.git
git clone https://github.com/s0md3v/Photon.git
# Findomain: download the release binary for your platform from GitHub releases
pip install dnsrecon
```

After installing any tools, re-run:

```bash
osintx update-tools
```

to confirm detection.

## 4. Configure AI provider

```bash
osintx config --init
$EDITOR ~/.osintx/config.yaml
```

Set `ai.provider` to `gemini`, `groq`, or `ollama`, and provide the
relevant API key via environment variable (see README).

## 5. (Optional) Enable port scanning

Port scanning (`nmap`) is disabled unless you explicitly authorize it per
run, via `--i-have-authorization`, and only against targets you own or are
contractually authorized to test.
