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
| `--no-ai` | Skip AI enrichment; report contains only collected facts |
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
Runs Sherlock (if installed) to find public profile URLs across
supported sites.

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
Runs WHOIS/ASN lookup always; runs a conservative nmap scan (top 100
ports, service detection) only when `--i-have-authorization` is passed.

### Company
```bash
osintx investigate --company "Example Corp"
```
Looks up the company's public GitHub organization (repos + languages) and
generates manual-review links (search engine, Crunchbase).

### Image
```bash
osintx investigate --image ./photo.jpg
```
Extracts EXIF/GPS/camera metadata, runs OCR (if Tesseract installed),
decodes QR codes, computes a SHA-256 file hash, and generates a reverse
image-search link template (upload manually — no scraping of search
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
