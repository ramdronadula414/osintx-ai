"""AI Engine — the only place in OSINT-X AI that talks to an LLM.

Strict rule enforced throughout this module: the AI is given ONLY the
already-collected, already-normalized facts (entities, tool outputs,
timeline) and asked to summarize/correlate/prioritize them. It is
explicitly instructed never to invent facts not present in the input, and
every AI-generated section in the final report is visually/structurally
separated from the raw collected-facts sections so a reader never confuses
the two.
"""
from __future__ import annotations

from config.loader import AIConfig
from ai.provider import AIProvider, AIProviderError
from ai.providers.gemini import GeminiProvider
from ai.providers.groq import GroqProvider
from ai.providers.ollama import OllamaProvider
from core.schema import Investigation

SYSTEM_PROMPT = """You are the analysis component of OSINT-X AI, a lawful, \
defensive OSINT reporting tool. You will be given a structured list of \
FACTS collected from public sources and Linux OSINT tools for one \
investigation target. Your job is strictly limited to:
  1. Summarizing what was found (executive + technical summaries).
  2. Correlating entities that plausibly belong to the same person/org.
  3. Flagging which conclusions are well-supported vs. uncertain.
  4. Suggesting further lawful, public-source investigation steps.

Hard rules:
  - Never state a fact that is not present in the provided data. If you are
    inferring or guessing, say so explicitly (e.g. "possibly", "unconfirmed").
  - Never provide instructions for unauthorized access, exploitation, \
    social engineering, or bypassing authentication.
  - Keep the tone neutral and analytical, like a security report, not \
    speculative journalism.
"""


def build_provider(config: AIConfig) -> AIProvider:
    if config.provider == "gemini":
        return GeminiProvider(api_key=config.gemini.api_key, model=config.gemini.model)
    if config.provider == "groq":
        return GroqProvider(api_key=config.groq.api_key, model=config.groq.model)
    return OllamaProvider(host=config.ollama.host, model=config.ollama.model)


def _facts_block(investigation: Investigation) -> str:
    lines = [f"TARGET: {investigation.target_type} = {investigation.target_value}", "", "ENTITIES FOUND:"]
    for e in investigation.entities:
        lines.append(f"- [{e.type.value}] {e.value} (source: {e.source}, confidence: {e.confidence})")

    lines.append("\nTOOL RESULTS:")
    for tr in investigation.tool_results:
        status = "success" if tr.success else f"failed ({tr.error})"
        lines.append(f"- {tr.tool}: {status}, {len(tr.entities)} entities")

    if investigation.timeline:
        lines.append("\nTIMELINE:")
        for ev in investigation.timeline:
            lines.append(f"- {ev.timestamp}: {ev.description} (source: {ev.source})")

    return "\n".join(lines)


class AIEngine:
    def __init__(self, config: AIConfig):
        self.config = config
        self.provider = build_provider(config)

    def is_available(self) -> bool:
        return self.provider.is_configured()

    def enrich(self, investigation: Investigation) -> Investigation:
        """Populate ai_summary, ai_technical_summary, and ai_recommendations
        on the investigation in place. Never raises — on failure it records
        a warning and leaves AI fields as None so the report generator can
        clearly show 'AI analysis unavailable'."""
        if not self.is_available():
            investigation.warnings.append(
                f"AI provider '{self.provider.name}' is not configured/reachable; "
                "report will contain collected facts only, no AI summary."
            )
            return investigation

        facts = _facts_block(investigation)

        try:
            investigation.ai_summary = self.provider.complete(
                SYSTEM_PROMPT,
                f"{facts}\n\nWrite a 4-6 sentence EXECUTIVE SUMMARY for a non-technical "
                "reader. Only use facts above.",
                max_tokens=400,
            )
            investigation.ai_technical_summary = self.provider.complete(
                SYSTEM_PROMPT,
                f"{facts}\n\nWrite a TECHNICAL SUMMARY correlating entities, noting "
                "confidence levels and any conflicting/uncertain data. Only use facts above.",
                max_tokens=600,
            )
            recs_text = self.provider.complete(
                SYSTEM_PROMPT,
                f"{facts}\n\nList 3-6 concrete, LAWFUL follow-up OSINT steps as a "
                "newline-separated list. No exploitation or unauthorized access steps.",
                max_tokens=300,
            )
            investigation.ai_recommendations = [
                line.strip("-• ").strip() for line in recs_text.splitlines() if line.strip()
            ]
        except AIProviderError as exc:
            investigation.warnings.append(f"AI enrichment failed: {exc}")

        return investigation
