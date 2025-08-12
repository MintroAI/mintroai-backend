"""
Audit logging middleware for tracking authentication operations and security events.
"""

from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import json
import uuid

from src.core.logger.logger import get_logger
from src.infra.config.redis import get_redis
from src.api.utils.metrics import get_metrics

logger = get_logger(__name__)


class AuditEvent:
    """Audit event data structure."""
    
    def __init__(
        self,
        event_id: str,
        event_type: str,
        ip_address: str,
        user_agent: str,
        endpoint: str,
        method: str,
        status_code: int,
        wallet_address: Optional[str] = None,
        protocol: Optional[str] = None,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
        request_data: Optional[Dict[str, Any]] = None,
        response_time_ms: Optional[float] = None,
        timestamp: Optional[datetime] = None
    ):
        self.event_id = event_id
        self.event_type = event_type
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.endpoint = endpoint
        self.method = method
        self.status_code = status_code
        self.wallet_address = wallet_address
        self.protocol = protocol
        self.error_code = error_code
        self.error_message = error_message
        self.request_data = request_data or {}
        self.response_time_ms = response_time_ms
        self.timestamp = timestamp or datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'endpoint': self.endpoint,
            'method': self.method,
            'status_code': self.status_code,
            'wallet_address': self.wallet_address,
            'protocol': self.protocol,
            'error_code': self.error_code,
            'error_message': self.error_message,
            'request_data': self.request_data,
            'response_time_ms': self.response_time_ms,
            'timestamp': self.timestamp.isoformat() + 'Z'
        }


class AuditLogger:
    """Handles audit logging for authentication operations."""
    
    def __init__(self):
        self.redis_client = None
        self._redis_initialized = False
    
    async def _ensure_redis(self):
        """Ensure Redis connection is initialized."""
        if not self._redis_initialized:
            try:
                self.redis_client = await get_redis()
                self._redis_initialized = True
            except Exception as e:
                logger.warning(f"Failed to initialize Redis for audit logging: {str(e)}")
                self.redis_client = None
    
    async def log_event(self, event: AuditEvent):
        """Log audit event to both logger and Redis."""
        try:
            # Log to application logger
            event_data = event.to_dict()
            logger.info(
                f"AUDIT: {event.event_type}",
                extra={
                    'audit_event': True,
                    **event_data
                }
            )
            
            # Store in Redis for analytics (optional)
            await self._store_in_redis(event)
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {str(e)}")
    
    async def _store_in_redis(self, event: AuditEvent):
        """Store audit event in Redis for analytics."""
        try:
            await self._ensure_redis()
            if self.redis_client:
                # Store with TTL of 30 days
                key = f"audit:event:{event.event_id}"
                await self.redis_client.setex(
                    key, 
                    30 * 24 * 60 * 60,  # 30 days in seconds
                    json.dumps(event.to_dict())
                )
                
                # Add to daily index for analytics
                date_key = f"audit:daily:{event.timestamp.strftime('%Y-%m-%d')}"
                await self.redis_client.sadd(date_key, event.event_id)
                await self.redis_client.expire(date_key, 30 * 24 * 60 * 60)
                
        except Exception as e:
            logger.warning(f"Failed to store audit event in Redis: {str(e)}")
    
    def _extract_request_data(self, request: Request, body: bytes) -> Dict[str, Any]:
        """Extract relevant request data for auditing."""
        data = {
            'headers': dict(request.headers),
            'query_params': dict(request.query_params),
            'path_params': getattr(request, 'path_params', {}),
        }
        
        # Try to parse request body for auth endpoints
        if request.url.path.startswith('/auth/') and body:
            try:
                if request.headers.get('content-type') == 'application/json':
                    body_data = json.loads(body.decode('utf-8'))
                    # Remove sensitive data
                    safe_data = {k: v for k, v in body_data.items() 
                               if k not in ['signature', 'private_key', 'secret']}
                    data['body'] = safe_data
            except Exception:
                data['body'] = '<invalid_json>'
        
        # Remove sensitive headers
        if 'authorization' in data['headers']:
            data['headers']['authorization'] = '<redacted>'
        
        return data
    
    def _determine_event_type(self, request: Request, status_code: int) -> str:
        """Determine audit event type based on request and response."""
        endpoint = request.url.path
        method = request.method
        
        if endpoint.startswith('/auth/'):
            if endpoint == '/auth/challenge':
                return 'CHALLENGE_REQUEST' if status_code < 400 else 'CHALLENGE_FAILED'
            elif endpoint == '/auth/verify':
                return 'AUTH_SUCCESS' if status_code < 400 else 'AUTH_FAILED'
            elif endpoint == '/auth/refresh':
                return 'TOKEN_REFRESH' if status_code < 400 else 'REFRESH_FAILED'
            elif endpoint == '/auth/logout':
                return 'LOGOUT' if status_code < 400 else 'LOGOUT_FAILED'
        
        if status_code == 429:
            return 'RATE_LIMIT_EXCEEDED'
        elif status_code == 403:
            return 'ACCESS_DENIED'
        elif status_code >= 500:
            return 'SYSTEM_ERROR'
        elif status_code >= 400:
            return 'CLIENT_ERROR'
        
        return 'API_REQUEST'
    
    def _update_metrics(self, event: AuditEvent):
        """Update metrics based on audit event."""
        try:
            metrics = get_metrics()
            
            # Record challenge creation
            if event.event_type == 'CHALLENGE_REQUEST':
                metrics.record_challenge_created(event.protocol or 'unknown')
            
            # Record authentication attempts
            elif event.event_type in ['AUTH_SUCCESS', 'AUTH_FAILED']:
                success = event.event_type == 'AUTH_SUCCESS'
                metrics.record_auth_attempt(event.protocol or 'unknown', success)
            
            # Record session changes
            elif event.event_type == 'AUTH_SUCCESS':
                metrics.record_session_change(1)  # Login
            elif event.event_type == 'LOGOUT':
                metrics.record_session_change(-1)  # Logout
                
        except Exception as e:
            logger.warning(f"Failed to update metrics: {str(e)}")


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for comprehensive audit logging."""
    
    def __init__(self, app):
        super().__init__(app)
        self.audit_logger = AuditLogger()
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP, handling proxies."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        return request.client.host if request.client else "unknown"
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip audit logging for health checks and docs
        if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)
        
        start_time = datetime.utcnow()
        event_id = str(uuid.uuid4())
        
        # Read request body for audit logging
        body = b""
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
                # Recreate request with body for downstream processing
                async def receive():
                    return {"type": "http.request", "body": body}
                request._receive = receive
            except Exception as e:
                logger.warning(f"Failed to read request body for audit: {str(e)}")
        
        # Process request
        response = await call_next(request)
        
        # Calculate response time
        end_time = datetime.utcnow()
        response_time_ms = (end_time - start_time).total_seconds() * 1000
        
        # Extract audit information
        ip_address = self._get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "unknown")
        request_data = self.audit_logger._extract_request_data(request, body)
        event_type = self.audit_logger._determine_event_type(request, response.status_code)
        
        # Extract wallet address and protocol from request if available
        wallet_address = None
        protocol = None
        error_code = None
        error_message = None
        
        if request.url.path.startswith('/auth/') and body:
            try:
                body_data = json.loads(body.decode('utf-8'))
                wallet_address = body_data.get('wallet_address')
                protocol = body_data.get('protocol')
            except Exception:
                pass
        
        # Extract error information from response if available
        if response.status_code >= 400:
            try:
                # This is a simplified approach - in real implementation,
                # you might want to capture response body for error details
                if response.status_code == 429:
                    error_code = "RATE_LIMIT_EXCEEDED"
                    error_message = "Rate limit exceeded"
                elif response.status_code == 403:
                    error_code = "ACCESS_DENIED"
                    error_message = "Access denied"
                elif response.status_code == 401:
                    error_code = "UNAUTHORIZED"
                    error_message = "Unauthorized access"
            except Exception:
                pass
        
        # Create and log audit event
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=event_type,
            ip_address=ip_address,
            user_agent=user_agent,
            endpoint=request.url.path,
            method=request.method,
            status_code=response.status_code,
            wallet_address=wallet_address,
            protocol=protocol,
            error_code=error_code,
            error_message=error_message,
            request_data=request_data,
            response_time_ms=response_time_ms,
            timestamp=start_time
        )
        
        # Log audit event asynchronously
        try:
            await self.audit_logger.log_event(audit_event)
            # Update metrics
            self.audit_logger._update_metrics(audit_event)
        except Exception as e:
            logger.error(f"Failed to process audit event: {str(e)}")
        
        # Add audit event ID to response headers for tracking
        response.headers["X-Audit-Event-ID"] = event_id
        
        return response
