import logging
import sys
from typing import Any, Dict
from functools import lru_cache

from src.infra.config.settings import settings


class Logger:
    def __init__(self, name: str = "MintroAI"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
        
        # Console Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
        )
        self.logger.addHandler(console_handler)
    
    def _log(self, level: int, message: str, extra: Dict[str, Any] = None) -> None:
        if extra is None:
            extra = {}
        self.logger.log(level, message, extra=extra)
    
    def info(self, message: str, extra: Dict[str, Any] = None) -> None:
        self._log(logging.INFO, message, extra)
    
    def error(self, message: str, extra: Dict[str, Any] = None) -> None:
        self._log(logging.ERROR, message, extra)
    
    def debug(self, message: str, extra: Dict[str, Any] = None) -> None:
        self._log(logging.DEBUG, message, extra)
    
    def warning(self, message: str, extra: Dict[str, Any] = None) -> None:
        self._log(logging.WARNING, message, extra)


@lru_cache()
def get_logger() -> Logger:
    return Logger()

logger = get_logger()