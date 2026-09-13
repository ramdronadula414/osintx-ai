from __future__ import annotations

from urllib.parse import urlsplit
from ai.provider import AIProvider, AIProviderError


class OllamaProvider(AIProvider):
    name = 'ollama'

    def __init__(self, host: str = 'http://localhost:11434', model: str = 'llama3.1', timeout: float = 30):
        self.host, self.model, self.timeout = host.rstrip('/'), model, timeout
        try:
            parsed = urlsplit(self.host)
            parsed.port
        except ValueError as exc:
            raise AIProviderError("Invalid Ollama host URL") from exc
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise AIProviderError('Invalid Ollama host URL')

    def is_configured(self) -> bool:
        return bool(self.host)

    def list_models(self) -> list[str]:
        data = self.request('GET', self.host + '/api/tags')
        if not isinstance(data, dict) or not isinstance(data.get('models'), list) or any(not isinstance(m, dict) or not isinstance(m.get('name'), str) for m in data['models']):
            raise AIProviderError('Malformed Ollama model list')
        names = [m['name'] for m in data['models']]
        return list(dict.fromkeys(names + [name.removesuffix(':latest') for name in names if name.endswith(':latest')]))

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> str:
        self.require_model()
        data = self.request('POST', self.host + '/api/chat', json={
            'model': self.model, 'messages': [{'role': 'system', 'content': system_prompt}, {'role': 'user', 'content': user_prompt}],
            'stream': False, 'options': {'num_predict': max_tokens, 'temperature': 0}})
        try:
            return self.text_response(data['message']['content'])
        except (TypeError, KeyError) as exc:
            raise AIProviderError('Malformed Ollama completion') from exc
