from __future__ import annotations

import requests

from ai.provider import AIProvider, AIProviderError


class GeminiProvider(AIProvider):
    name = "gemini"

    def __init__(self, api_key: str | None, model: str = "gemini-1.5-flash"):
        self.api_key = api_key
        self.model = model
        self.base_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> str:
        if not self.is_configured():
            raise AIProviderError("Gemini API key is not configured (set GEMINI_API_KEY).")

        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.2},
        }
        try:
            resp = requests.post(
                self.base_url,
                params={"key": self.api_key},
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise AIProviderError("Gemini returned no candidates.")
            parts = candidates[0].get("content", {}).get("parts", [])
            return "".join(p.get("text", "") for p in parts).strip()
        except requests.RequestException as exc:
            raise AIProviderError(f"Gemini request failed: {exc}") from exc
