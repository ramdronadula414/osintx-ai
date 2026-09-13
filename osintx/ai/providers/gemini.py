from __future__ import annotations

from urllib.parse import quote
from ai.provider import AIProvider, AIProviderError


class GeminiProvider(AIProvider):
    name = 'gemini'

    def __init__(self, api_key: str | None, model: str = '', timeout: float = 30):
        self.api_key, self.model, self.timeout = api_key, model.removeprefix('models/'), timeout
        self.base_url = 'https://generativelanguage.googleapis.com/v1beta/models'

    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def list_models(self) -> list[str]:
        if not self.is_configured():
            from core.schema import ResultStatus
            raise AIProviderError('Set GEMINI_API_KEY or GOOGLE_API_KEY', ResultStatus.TOOL_UNAVAILABLE)
        data = self.request('GET', self.base_url, headers={'x-goog-api-key': self.api_key}, params={'pageSize': 1000})
        if not isinstance(data, dict) or not isinstance(data.get('models'), list):
            raise AIProviderError('Malformed Gemini model list')
        models = data['models']
        if any(not isinstance(m, dict) or not isinstance(m.get('name'), str) or not isinstance(m.get('supportedGenerationMethods', []), list) for m in models):
            raise AIProviderError('Malformed Gemini model record')
        if data.get('nextPageToken'):
            raise AIProviderError('Gemini model list exceeds supported page limit; configure a smaller catalogue or retry')
        return [m['name'].removeprefix('models/') for m in models if 'generateContent' in m.get('supportedGenerationMethods', [])]

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> str:
        self.require_model()
        data = self.request('POST', self.base_url + '/' + quote(self.model, safe='') + ':generateContent',
                            headers={'x-goog-api-key': self.api_key}, json={
                                'system_instruction': {'parts': [{'text': system_prompt}]},
                                'contents': [{'role': 'user', 'parts': [{'text': user_prompt}]}],
                                'generationConfig': {'maxOutputTokens': max_tokens, 'temperature': 0}})
        try:
            parts = data['candidates'][0]['content']['parts']
            if not isinstance(parts, list) or any(not isinstance(p, dict) or not isinstance(p.get('text', ''), str) for p in parts):
                raise TypeError
            return self.text_response(''.join(p.get('text', '') for p in parts))
        except (TypeError, KeyError, IndexError) as exc:
            raise AIProviderError('Malformed or blocked Gemini completion') from exc
