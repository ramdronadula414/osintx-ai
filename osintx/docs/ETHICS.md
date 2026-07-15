# Ethics & Scope

OSINT-X AI is designed strictly as a **lawful, defensive OSINT automation
framework**. It is intended for security analysts, SOC teams,
authorized penetration testers, digital forensics investigators,
journalists, researchers, and students learning OSINT methodology.

## What OSINT-X AI does

- Automates public-source data collection an analyst could otherwise do
  by hand: WHOIS, public DNS records, public username/profile search,
  public GitHub organization data, EXIF metadata from images you already
  possess, and similar.
- Correlates and summarizes that data with AI, always keeping AI-generated
  content visually and structurally separate from raw collected facts.
- Generates reports for legitimate investigation, incident response, or
  educational documentation purposes.

## What OSINT-X AI refuses to do, by design

- **No authentication bypass.** It never logs into or scrapes content
  behind a login wall.
- **No unauthorized scanning.** Port scanning via nmap requires the
  operator to pass `--i-have-authorization` on every single run,
  confirming they own or are contractually authorized to test the target.
- **No credential/breach-database lookups.** Email investigation is
  limited to syntax validation and public DNS records (MX/SPF/DMARC/WHOIS)
  — it will not query leaked-credential databases.
- **No search-engine scraping.** Person/company search generates
  manual-review search URLs instead of scraping search-result pages,
  respecting each platform's terms of service.
- **No fact fabrication.** The AI engine's system prompt explicitly
  forbids stating anything not present in the already-collected data, and
  requires it to flag uncertain/inferred conclusions as such.

## Your responsibility as the operator

You are responsible for ensuring your use of this tool complies with:

- The laws of your jurisdiction and the target's jurisdiction.
- The terms of service of any platform your investigation touches.
- Any employment, client, or research-ethics agreements governing your
  work.

When in doubt, treat any target as out of scope until you have explicit,
documented authorization.
