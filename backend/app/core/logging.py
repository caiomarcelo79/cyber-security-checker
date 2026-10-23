"""Configuração de logs estruturados para observabilidade e trilha de auditoria."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime


class StructuredJsonFormatter(logging.Formatter):
    """Formata registros de log em JSON estruturado sem expor segredos."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    """Inicializa o logger raiz com formatação estruturada."""
    root_logger = logging.getLogger()
    if root_logger.handlers:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredJsonFormatter())
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
