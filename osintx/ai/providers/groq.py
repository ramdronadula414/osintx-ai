from __future__ import annotations

from ai.provider import AIProvider, AIProviderError
from core.schema import ResultStatus


class GroqProvider(AIProvider):
    name = 'groq'

    def __init__(self, api_key: str | None, model: str = '', timeout: float = 30):
        self.api_key, self.model, self.timeout = api_key, model, timeout
        self.base_url = 'https://api.groq.com/openai/v1'

    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def list_models(self) -> list[str]:
        if not self.is_configured():
            raise AIProviderError('Set GROQ_API_KEY', ResultStatus.TOOL_UNAVAILABLE)
        data = self.request('GET', self.base_url + '/models', headers={'Authorization': f'Bearer {self.api_key}'})
        if not isinstance(data, dict) or not isinstance(data.get('data'), list) or any(not isinstance(m, dict) or not isinstance(m.get('id'), str) for m in data['data']):
            raise AIProviderError('Malformed Groq model list')
        return [m['id'] for m in data['data'] if m.get('active', True)]

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> str:
        self.require_model()
        data = self.request('POST', self.base_url + '/chat/completions',
                            headers={'Authorization': f'Bearer {self.api_key}'}, json={
                                'model': self.model, 'messages': [{'role': 'system', 'content': system_prompt}, {'role': 'user', 'content': user_prompt}],
                                'max_tokens': max_tokens, 'temperature': 0})
        try:
            return self.text_response(data['choices'][0]['message']['content'])
        except (TypeError, KeyError, IndexError) as exc:
            raise AIProviderError('Malformed Groq completion') from exc
