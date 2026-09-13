"""Redacted text/JSON logging; unavailable log storage never stops collection."""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from rich.console import Console
from rich.logging import RichHandler


def redact(value: str) -> str:
    for key, secret in os.environ.items():
        if secret and len(secret) >= 4 and any(word in key.upper() for word in ('API_KEY', 'TOKEN', 'PASSWORD', 'SECRET')):
            value = value.replace(secret, '[REDACTED]')
    value = re.sub(r'(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+', r'\1[REDACTED]', value)
    return re.sub(r'(?i)([?&](?:key|api_key|token)=)[^&\s]+', r'\1[REDACTED]', value)


class RedactFilter(logging.Filter):
    def filter(self, record):
        record.msg = redact(record.getMessage())
        record.args = ()
        # Exception strings may contain headers or URL credentials. Log their type only.
        if record.exc_info:
            record.msg += f' ({record.exc_info[0].__name__})'
            record.exc_info = None
            record.exc_text = None
        return True


class JsonLineHandler(logging.Handler):
    def __init__(self, path: Path):
        super().__init__()
        self.path = path

    def emit(self, record):
        try:
            with self.path.open('a', encoding='utf-8') as stream:
                stream.write(json.dumps({'timestamp': datetime.now(timezone.utc).isoformat(),
                                         'level': record.levelname, 'logger': record.name,
                                         'message': redact(record.getMessage())}) + '\n')
        except OSError:
            # The console handler remains active; avoid recursive logging failures.
            return  # Console handler remains active; avoid recursive logging failures.


class SafeFileHandler(logging.FileHandler):
    def handleError(self, record):
        return  # Console logging remains available if disk fills during a run.


def setup_logging(log_dir: str = './logs', level: str = 'INFO') -> logging.Logger:
    logger = logging.getLogger('osintx')
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)
    logger.propagate = False
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = RichHandler(console=Console(stderr=True), show_path=False, rich_tracebacks=False, markup=False)
    handler.addFilter(RedactFilter())
    logger.addHandler(handler)
    try:
        path = Path(log_dir).expanduser()
        path.mkdir(parents=True, exist_ok=True)
        file_handler = SafeFileHandler(path / 'osintx.log', encoding='utf-8')
        file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
        for handler in (file_handler, JsonLineHandler(path / 'osintx.jsonl')):
            handler.addFilter(RedactFilter())
            logger.addHandler(handler)
    except OSError:
        logger.warning('Log directory unavailable; continuing with console logging')
    return logger


def get_logger(name: str = 'osintx') -> logging.Logger:
    return logging.getLogger(name if name.startswith('osintx') else 'osintx.' + name)
