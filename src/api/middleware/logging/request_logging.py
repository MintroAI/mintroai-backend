import time
import json
import traceback
from datetime import datetime
from typing import Optional
from uuid import uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from src.core.logger.logger import logger

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Start timing
        start_time = time.time()
        
        # Get or generate correlation ID
        correlation_id = request.headers.get("X-Request-ID", str(uuid4()))
        
        # Create log context
        log_context = {
            "request_id": correlation_id,
            "method": request.method,
            "path": request.url.path,
            "client_ip": request.client.host,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        response: Optional[Response] = None
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration_ms = round((time.time() - start_time) * 1000, 2)
            
            # Log successful request
            log_context.update({
                "status_code": response.status_code,
                "duration_ms": duration_ms
            })
            
            # Add custom header
            response.headers["X-Request-ID"] = correlation_id
            
            logger.info(json.dumps(log_context))
            
            return response
            
        except Exception as e:
            # Log error with stack trace
            duration_ms = round((time.time() - start_time) * 1000, 2)
            log_context.update({
                "error": str(e),
                "error_type": e.__class__.__name__,
                "stack_trace": traceback.format_exc(),
                "duration_ms": duration_ms
            })
            logger.error(json.dumps(log_context))
            raise