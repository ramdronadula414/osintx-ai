from __future__ import annotations

import requests

from ai.provider import AIProvider, AIProviderError


class GroqProvider(AIProvider):
    name = "groq"

    def __init__(self, api_key: str | None, model: str = "llama-3.1-70b-versatile"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> str:
        if not self.is_configured():
            raise AIProviderError("Groq API key is not configured (set GROQ_API_KEY).")

        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
        try:
            resp = requests.post(self.base_url, headers=headers, json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()
        except (requests.RequestException, KeyError, IndexError) as exc:
            raise AIProviderError(f"Groq request failed: {exc}") from exc
