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
from typing import Optional

import yaml
from pydantic import BaseModel, Field

_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"
USER_CONFIG_PATH = Path.home() / ".osintx" / "config.yaml"


class GeneralConfig(BaseModel):
    output_dir: str = "./exports"
    cache_dir: str = "./cache"
    log_dir: str = "./logs"
    log_level: str = "INFO"
    threads: int = 8
    timeout_seconds: int = 30
    proxy: Optional[str] = None


class GeminiConfig(BaseModel):
    api_key: Optional[str] = None
    model: str = "gemini-1.5-flash"


class GroqConfig(BaseModel):
    api_key: Optional[str] = None
    model: str = "llama-3.1-70b-versatile"


class OllamaConfig(BaseModel):
    host: str = "http://localhost:11434"
    model: str = "llama3.1"


class AIConfig(BaseModel):
    provider: str = "ollama"
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
    tools: dict = Field(default_factory=dict)
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


def load_config(extra_path: Optional[str] = None) -> AppConfig:
    """Load and merge configuration from default, user, and optional extra paths."""
    with open(DEFAULT_CONFIG_PATH, "r") as f:
        data = yaml.safe_load(f) or {}

    if USER_CONFIG_PATH.exists():
        with open(USER_CONFIG_PATH, "r") as f:
            user_data = yaml.safe_load(f) or {}
        data = _deep_merge(data, user_data)

    if extra_path:
        extra_file = Path(extra_path)
        if extra_file.exists():
            with open(extra_file, "r") as f:
                extra_data = yaml.safe_load(f) or {}
            data = _deep_merge(data, extra_data)

    data = _expand_env(data)
    return AppConfig(**data)


def ensure_user_config():
    """Create ~/.osintx/config.yaml from the default template if it doesn't exist."""
    if not USER_CONFIG_PATH.exists():
        USER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        USER_CONFIG_PATH.write_text(DEFAULT_CONFIG_PATH.read_text())
    return USER_CONFIG_PATH
