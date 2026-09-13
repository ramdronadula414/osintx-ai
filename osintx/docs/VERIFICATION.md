# Verification record — reliability and accuracy fixes

Date: 2026-09-13. Base: `cdc920eda74102551e5dfdf9e38317e79212e45f` on `main`.

## Audit coverage

Read all 74 original repository files: CLI/entry point, seven modules, six dedicated tool wrappers, bundled crt.sh plugin and plugin loader, three AI providers, schema/orchestrator, configuration, normalization/risk/timeline/extraction engines, six report formats, SQLite history, logging, requirements/build metadata, docs and tests.

Reproduced before editing:

- Startup failed without required dependencies; after installing original requirements, original help and 26 tests passed.
- Invalid domain input returned a completed investigation instead of a validation error.
- Sherlock accepted a URL from an error line and marked a failed command successful.
- A failed dig command retained parsed findings.
- Subprocess timeout stdout was bytes even though downstream parsers expected strings.

Code inspection also found suggested URLs labeled as raw facts, input emails counted as confirmed intelligence, DNS fields omitted, arbitrary confidence inflation, malformed API shape crashes, unbounded output capture, optional PDF/DOCX imports required at startup, exposed resolved API keys, conflicting dependency pins, and missing wheel configuration data.

## Executed checks

| Check | Result |
|---|---|
| Python runtime | CPython 3.12.14 on Linux |
| Original requirements installation | Passed in an isolated virtual environment |
| Updated requirements/editable installation | Passed; core dependencies shared with pyproject metadata |
| Regression suite | **177 passed** |
| Python compile/import checks | Passed; all 44 discovered production modules imported with report extras installed |
| Python 3.10 grammar parsing | Passed for 65 source/test files; not a Python 3.10 runtime test |
| CLI | Startup, help, version, tool detection, invalid/multiple/empty target handling, all seven modules, offline mode, history/report commands |
| Input/security | Invalid IPv4/IPv6/domain/email/username/URL, option injection, Unicode names/IDNA, argv shell-literal behavior, output bounds |
| Failure behavior | Missing binaries/keys, invalid AI key HTTP responses, 401/403/404/429/5xx, malformed API/ExifTool shapes, DNS errors/timeouts, command timeout, empty output, permission/report/history errors |
| Cancellation | Real subprocess SIGINT test verifies child process-group cleanup; CLI Ctrl+C produces exit 130 |
| AI accuracy | Unknown evidence IDs and malformed/free-form output rejected; only existing evidence and predefined actions rendered |
| Reports | JSON/Markdown/HTML/CSV/DOCX/PDF generation executed; status separation and HTML/CSV injection protection checked; optional renderer failure preserves other outputs |
| Package | Wheel built; bundled default config/plugin present; installed into a second environment without report/QR extras; CLI and four core report formats executed outside source directory |
| Dependency consistency | `pip check` passed |
| Source diff | Whitespace checks passed; changes reviewed |
| Credential pattern history scan | All three original commits, 62 unique blobs: no matches for checked Gemini/Groq/GitHub/OpenRouter key formats or private-key headers |

Tests use synthetic fixtures, mocked external services, and explicit isolated temporary files. Passing them does not validate a real API credential or a third-party website's current behavior.

## Local smoke runs with actual environment state

- Person: generated encoded search suggestions, zero discoveries.
- Username: missing Sherlock/Maigret explicitly reported as TOOL UNAVAILABLE, zero discoveries.
- Email/domain: absent binaries and actual DNS/network failures classified without crashes. crt.sh attempt timed out with no discoveries.
- Company: public GitHub API attempt timed out with no discoveries; search suggestions retained.
- IP: documentation-range address skipped for public lookups; unauthorized Nmap step skipped.
- Image: actual Tesseract OCR and SHA-256 completed on a generated local test image; OCR remained UNVERIFIED. Missing ExifTool/QR dependencies did not block hashing/OCR. Pillow EXIF fallback separately exercised using a synthetic metadata fixture.

## NOT VERIFIED IN CURRENT ENVIRONMENT

- Live Sherlock, theHarvester, whois, dig, ExifTool, Maigret and Nmap execution: binaries absent. No active scan was performed.
- Live successful public DNS, crt.sh or company GitHub API collection: network restrictions/timeouts prevented validation. Parsing and error paths were exercised with fixtures.
- Live Gemini/Groq/Ollama generation and model catalogues: no configured service credentials/local Ollama server. Provider behavior was tested with mocked responses.
- Native QR decoding: libzbar absent; graceful dependency handling was executed.
- Python 3.10, 3.11 and 3.13 runtime compatibility: CI matrix added, but those runtimes were not executed locally. CI status must be checked after publishing.
- Exhaustive credential detection: the scan is pattern-based and cannot prove that all possible secret formats are absent.

## Remaining design limits

Person queries provide suggestions only. Company affiliation and username matches remain unverified. Certificate names may be historical or wildcard-only. Embedded metadata may be edited. Pillow fallback reads top-level EXIF. Native image libraries and trusted drop-in plugins are not sandboxed. Confidence defaults to unassessed; repeated sources do not boost it. HTTP/system-tool coverage depends on network and installed versions. Detection-only tools are explicitly documented. No application can guarantee that an external source is truthful; these changes enforce provenance and prevent unverified/AI output from being presented as confirmed discoveries.
