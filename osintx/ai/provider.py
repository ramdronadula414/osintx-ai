"""Optional AI providers; all failures carry the same source status taxonomy."""
from __future__ import annotations

from abc import ABC, abstractmethod
from core.schema import ResultStatus
from utils.http import SourceError, request_json


class AIProviderError(SourceError):
    def __init__(self, message: str, status: ResultStatus = ResultStatus.API_ERROR):
        super().__init__(status, message)


class AIProvider(ABC):
    name: str = 'base'

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> str:
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        pass

    @abstractmethod
    def list_models(self) -> list[str]:
        pass

    def request(self, method, url, **kwargs):
        try:
            return request_json(method, url, timeout=self.timeout, **kwargs)
        except SourceError as exc:
            # A missing API route/model is not an OSINT NOT FOUND observation.
            status = ResultStatus.API_ERROR if exc.status == ResultStatus.NOT_FOUND else exc.status
            raise AIProviderError(f'{self.name}: {exc}', status) from exc

    def require_model(self):
        if not self.is_configured():
            raise AIProviderError(f'{self.name} API key/host is not configured', ResultStatus.TOOL_UNAVAILABLE)
        if not self.model:
            raise AIProviderError(f'Set a model for {self.name}; run osintx models --provider {self.name}')
        if not getattr(self, '_model_checked', False):
            if self.model not in self.list_models():
                raise AIProviderError(f'Configured {self.name} model is unavailable; run osintx models --provider {self.name}')
            self._model_checked = True

    def text_response(self, value):
        if not isinstance(value, str) or not value.strip():
            raise AIProviderError(f'{self.name} returned empty or malformed text')
        return value.strip()
