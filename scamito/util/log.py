"""Configure application-wide JSON logging."""

from __future__ import annotations

import logging
import os
import sys

import json_log_formatter

_configured = False


class JSONFormatter(json_log_formatter.JSONFormatter):
    def json_record(self, message, extra, record):
        extra["name"] = record.name
        extra = super().json_record(message, extra, record)
        ordered = {}
        for key in ("time", "name", "message"):
            if key in extra:
                ordered[key] = extra.pop(key)
        ordered.update(extra)
        return ordered


def setup_logging() -> None:
    global _configured
    if _configured:
        return
    _configured = True

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
