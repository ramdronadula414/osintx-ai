"""Abstract AI provider interface. Gemini, Groq, and Ollama backends all
implement `complete()` so the rest of the AI engine never needs to know
which provider is configured."""
from __future__ import annotations

from abc import ABC, abstractmethod


class AIProviderError(Exception):
    pass


class AIProvider(ABC):
    name: str = "base"

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> str:
        """Send a prompt and return the raw text completion."""

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if this provider has what it needs (API key / reachable host)."""
