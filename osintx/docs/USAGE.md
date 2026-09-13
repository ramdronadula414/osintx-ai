# Usage Guide

## General command shape

```bash
osintx investigate --<target-type> "<value>" [options]
```

Exactly one target-type flag is required per invocation:
`--name`, `--username`, `--email`, `--phone`, `--domain`, `--ip`,
`--company`, `--image`.

## Options

| Flag | Description |
|---|---|
| `--output-dir PATH` | Override the configured output directory for this run |
| `--formats FMT,FMT` | Comma-separated subset of `markdown,json,csv,html,docx,pdf` |
| `--no-ai` | Skip AI prioritization |
| `--offline` | Skip network collection and AI; keep local image processing and search suggestions |
| `--i-have-authorization` | Required to run nmap against an `--ip` target |

## Examples

### Person
```bash
osintx investigate --name "Jane Smith"
```
Generates manual-review search-engine URLs (Google/Bing/DuckDuckGo/GitHub/
LinkedIn) rather than scraping results directly.

### Username
```bash
osintx investigate --username janedoe123
```
Runs Sherlock (if installed) and records candidate URLs as UNVERIFIED. A match does not prove account existence or identity. Maigret output remains diagnostic only.

### Email
```bash
osintx investigate --email jane@example.com
```
Validates syntax and checks public MX/SPF/DMARC/WHOIS records. No
credential or breach-database lookups are performed.

### Domain
```bash
osintx investigate --domain example.com --formats markdown,pdf
```
Runs WHOIS, full DNS record enumeration (A/AAAA/MX/NS/TXT/CNAME/SOA),
theHarvester (subdomains/emails from public sources), and the bundled
crt.sh certificate-transparency plugin.

### IP address
```bash
osintx investigate --ip 203.0.113.10 --i-have-authorization
```
Runs WHOIS/PTR for global addresses; skips public lookups for non-global addresses; runs a conservative nmap scan (top 100
ports, service detection) only when `--i-have-authorization` is passed.

### Company
```bash
osintx investigate --company "Example Corp"
```
Queries a GitHub organization-name candidate and generates search suggestions. Repository fields come from the API; the relationship between candidate and company remains UNVERIFIED. At most 30 repositories are returned.

### Image
```bash
osintx investigate --image ./photo.jpg
```
Extracts embedded metadata (Pillow fallback when ExifTool is absent), runs OCR (if Tesseract installed),
decodes QR codes, computes a SHA-256 file hash, and generates a reverse
image-search suggestion (upload manually — no scraping of search
providers).

## Reviewing past investigations

```bash
osintx history                 # list recent investigations
osintx report latest           # show the most recent investigation as JSON
osintx report <investigation-id>
```

## Checking tool availability

```bash
osintx update-tools
```

Missing tools are skipped gracefully during investigations; install more
of them following [docs/INSTALL.md](INSTALL.md) to increase coverage.

Inspect available AI models with `osintx models --provider groq` (or `gemini` / `ollama`). See [CONFIGURATION.md](CONFIGURATION.md) for environment variables.

Reports separate confirmed source observations, unverified candidates, suggestions, and per-source failures. Confidence is unassessed by default; it is never randomly assigned or increased by duplicate results. See the README for status definitions.
