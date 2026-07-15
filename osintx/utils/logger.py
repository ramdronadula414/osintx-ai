"""Structured logging for OSINT-X AI.

Writes human-readable logs to console (via rich), plain text logs to
logs/osintx.log, and machine-readable JSON lines to logs/osintx.jsonl for
later ingestion/audit.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.logging import RichHandler


class JsonLineHandler(logging.Handler):
    def __init__(self, path: Path):
        super().__init__()
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, record: logging.LogRecord):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.format(record)
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")


_configured = False


def setup_logging(log_dir: str = "./logs", level: str = "INFO") -> logging.Logger:
    global _configured
    logger = logging.getLogger("osintx")
    if _configured:
        return logger

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    rich_handler = RichHandler(rich_tracebacks=True, show_path=False)
    rich_handler.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_path / "osintx.log")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )

    json_handler = JsonLineHandler(log_path / "osintx.jsonl")

    logger.addHandler(rich_handler)
    logger.addHandler(file_handler)
    logger.addHandler(json_handler)

    _configured = True
    return logger


def get_logger(name: str = "osintx") -> logging.Logger:
    return logging.getLogger(name)
