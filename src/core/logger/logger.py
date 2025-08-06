import logging
import sys
import json
from typing import Any, Dict
from functools import lru_cache

from src.infra.config.settings import settings

class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    def format(self, record: logging.LogRecord) -> str:
        # Base log data
        log_data = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name
        }
        
        # Add message if it's not already JSON
        try:
            if isinstance(record.msg, str) and record.msg.startswith("{"):
                log_data.update(json.loads(record.msg))
            else:
                log_data["message"] = record.getMessage()
        except (json.JSONDecodeError, AttributeError):
            log_data["message"] = record.getMessage()
            
        # Add extra fields if present
        if hasattr(record, "request_id"):
            log_data["request_id"] = record.request_id
            
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
            
        # Add extra fields from record
        if record.args and isinstance(record.args, dict):
            log_data.update(record.args)
        
        return json.dumps(log_data)

class Logger:
    def __init__(self, name: str = "MintroAI"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
        self.logger.propagate = True  # Allow logs to propagate to parent loggers
        
        # Console Handler with JSON formatting
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(JsonFormatter())
        self.logger.addHandler(console_handler)
    
    def _log(self, level: int, message: Any, extra: Dict[str, Any] = None) -> None:
        if extra is None:
            extra = {}
            
        # If message is a dict, convert to JSON string
        if isinstance(message, dict):
            message = json.dumps(message)
            
        self.logger.log(level, message, extra=extra)
    
    def info(self, message: Any, extra: Dict[str, Any] = None) -> None:
        self._log(logging.INFO, message, extra)
    
    def error(self, message: Any, extra: Dict[str, Any] = None) -> None:
        self._log(logging.ERROR, message, extra)
    
    def warning(self, message: Any, extra: Dict[str, Any] = None) -> None:
        self._log(logging.WARNING, message, extra)
    
    def debug(self, message: Any, extra: Dict[str, Any] = None) -> None:
        self._log(logging.DEBUG, message, extra)

# Global logger instance
logger = Logger()

@lru_cache()
def get_logger(name: str = None) -> Logger:
    """Get a logger instance with optional name"""
    return Logger(name) if name else logger