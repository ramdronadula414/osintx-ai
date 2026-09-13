"""
Configuration loader for OSINT-X AI.

Loads config/config.yaml, overlays a user config at ~/.osintx/config.yaml
if present, expands ${ENV_VAR} references, and validates the result with
pydantic models so the rest of the codebase gets a typed, predictable
object instead of a raw dict.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional, Literal

import yaml
from pydantic import BaseModel, Field, SecretStr, ValidationError as ModelValidationError

_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"
USER_CONFIG_PATH = Path.home() / ".osintx" / "config.yaml"


class GeneralConfig(BaseModel):
    output_dir: str = "./exports"
    cache_dir: str = "./cache"
    log_dir: str = "./logs"
    log_level: str = "INFO"
    threads: int = Field(8, ge=1, le=64)
    timeout_seconds: int = Field(30, ge=1, le=300)
    proxy: Optional[str] = None


class GeminiConfig(BaseModel):
    api_key: Optional[SecretStr] = None
    model: str = ""


class GroqConfig(BaseModel):
    api_key: Optional[SecretStr] = None
    model: str = ""


class OllamaConfig(BaseModel):
    host: str = "http://localhost:11434"
    model: str = "llama3.1"


class AIConfig(BaseModel):
    provider: Literal["gemini", "groq", "ollama"] = "ollama"
    timeout_seconds: int = Field(30, ge=1, le=300)
    gemini: GeminiConfig = Field(default_factory=GeminiConfig)
    groq: GroqConfig = Field(default_factory=GroqConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)


class ToolsConfig(BaseModel):
    # None means "auto-detect via PATH"
    model_config = {"extra": "allow"}


class ReportsConfig(BaseModel):
    formats: list[str] = Field(default_factory=lambda: ["markdown", "json", "html"])
    include_raw_tool_output: bool = True


class SecurityConfig(BaseModel):
    allow_port_scanning: bool = False
    rate_limit_per_host_seconds: float = 1.0


class AppConfig(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    tools: dict[str, Optional[str]] = Field(default_factory=dict)
    reports: ReportsConfig = Field(default_factory=ReportsConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)


def _expand_env(value):
    if isinstance(value, str):
        match = _ENV_PATTERN.fullmatch(value.strip())
        if match:
            return os.environ.get(match.group(1))
        return value
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def _deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


class ConfigError(ValueError):
    pass


def load_config(extra_path: Optional[str] = None) -> AppConfig:
    data = {}
    try:
        for path in (DEFAULT_CONFIG_PATH, USER_CONFIG_PATH, Path(extra_path).expanduser() if extra_path else None):
            if path is None:
                continue
            if not path.exists() and path == USER_CONFIG_PATH:
                continue
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            if loaded is None:
                loaded = {}
            if not isinstance(loaded, dict):
                raise ConfigError("Configuration root must be a mapping")
            data = _deep_merge(data, loaded)
        data = _expand_env(data)
        ai = data.setdefault('ai', {})
        if not isinstance(ai, dict):
            raise ConfigError("ai configuration must be a mapping")
        for provider, key in [('gemini', os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')), ('groq', os.getenv('GROQ_API_KEY'))]:
            section = ai.setdefault(provider, {})
            if not isinstance(section, dict):
                raise ConfigError("AI provider configuration must be a mapping")
            section['api_key'] = key  # Environment only: never load literal credentials from YAML.
            model = os.getenv(provider.upper() + '_MODEL')
            if model:
                section['model'] = model
        if os.getenv('OSINTX_AI_PROVIDER'):
            ai['provider'] = os.environ['OSINTX_AI_PROVIDER']
        return AppConfig(**data)
    except (OSError, yaml.YAMLError, ModelValidationError, TypeError, UnicodeError) as exc:
        # Validation errors can include the original secret-bearing input. Do not print them.
        raise ConfigError(f"Unable to load configuration ({type(exc).__name__}); check YAML types, paths, and timeout bounds") from exc


def ensure_user_config():
    """Create ~/.osintx/config.yaml from the default template if it doesn't exist."""
    if not USER_CONFIG_PATH.exists():
        USER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        USER_CONFIG_PATH.write_text(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        USER_CONFIG_PATH.chmod(0o600)
    return USER_CONFIG_PATH
