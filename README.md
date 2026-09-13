# OSINT-X AI

Linux/Kali CLI for public-source OSINT collection, evidence tracking, optional AI prioritization, and investigation reports.

The Python project lives in [`osintx/`](osintx/). Start with its [README](osintx/README.md), [installation guide](osintx/docs/INSTALL.md), and [verification record](osintx/docs/VERIFICATION.md).

```bash
git clone https://github.com/ramdronadula414/osintx-ai.git
cd osintx-ai/osintx
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
osintx --help
osintx investigate --domain example.com --no-ai
```

Use only public sources and owned/authorized assets. Active IP scanning requires explicit authorization on each invocation. Candidate profiles and generated search links are never confirmed findings.
