"""Logging setup for PENTRIX ARSENAL.

One logger ("arsenal") with two sinks: a rotating file at
~/.arsenal/arsenal.log (always DEBUG) and stderr (INFO, or DEBUG with
--verbose). Every line is JSON with timestamp, level, module, message.
"""

import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

LOG_PATH = os.path.expanduser("~/.arsenal/arsenal.log")


class _JsonLineFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(payload)


def setup(verbose=False):
    """Return the configured "arsenal" logger (idempotent)."""
    logger = logging.getLogger("arsenal")
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    if logger.handlers:
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(
                    handler, RotatingFileHandler):
                handler.setLevel(level)
        return logger
    logger.propagate = False
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    formatter = _JsonLineFormatter()

    file_handler = RotatingFileHandler(
        LOG_PATH, maxBytes=1024 * 1024, backupCount=3, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setLevel(level)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger
