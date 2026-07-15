from __future__ import annotations

import requests

from ai.provider import AIProvider, AIProviderError


class OllamaProvider(AIProvider):
    """Local/offline provider — talks to a locally running Ollama server.
    Preferred for investigations where no data should leave the analyst's
    machine."""
    name = "ollama"

    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3.1"):
        self.host = host.rstrip("/")
        self.model = model

    def is_configured(self) -> bool:
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=3)
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {"num_predict": max_tokens, "temperature": 0.2},
        }
        try:
            resp = requests.post(f"{self.host}/api/chat", json=payload, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            return data.get("message", {}).get("content", "").strip()
        except requests.RequestException as exc:
            raise AIProviderError(
                f"Ollama request failed ({exc}). Is `ollama serve` running and is "
                f"'{self.model}' pulled?"
            ) from exc
