from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import json

from src.infra.config.settings import get_settings
from src.core.logger.logger import get_logger
from src.api.controller.auth.dto.error_responses import RateLimitErrorResponse, ErrorDetail, ErrorCode

logger = get_logger(__name__)
settings = get_settings()

class EnhancedRateLimiter:
    """Enhanced rate limiter with endpoint-specific limits and detailed tracking."""
    
    def __init__(self):
        # Endpoint-specific request tracking: endpoint -> IP -> timestamps
        self.endpoint_requests: Dict[str, Dict[str, list]] = {}
        self.blocked_ips: Dict[str, datetime] = {}  # IP -> Unblock time
        self.failed_attempts: Dict[str, Tuple[int, datetime]] = {}  # IP -> (count, first_attempt)
        
        # Endpoint-specific rate limits (requests per minute)
        self.endpoint_limits = {
            '/auth/challenge': 5,  # 5 challenges per minute
            '/auth/verify': 3,     # 3 verify attempts per minute
            '/auth/refresh': 10,   # 10 refresh attempts per minute
            '/auth/logout': 20,    # 20 logout attempts per minute
            'default': 30          # Default limit for other endpoints
        }

    def is_rate_limited(self, ip: str, endpoint: str) -> Tuple[bool, int, int, Optional[datetime]]:
        """
        Check if IP is rate limited for specific endpoint.
        Returns: (is_limited, current_count, limit, reset_time)
        """
        now = datetime.utcnow()
        
        # Check if IP is blocked
        if ip in self.blocked_ips:
            if now < self.blocked_ips[ip]:
                return True, 0, 0, self.blocked_ips[ip]
            else:
                del self.blocked_ips[ip]
        
        # Get endpoint-specific limit
        limit = self.endpoint_limits.get(endpoint, self.endpoint_limits['default'])
        
        # Initialize endpoint tracking if needed
        if endpoint not in self.endpoint_requests:
            self.endpoint_requests[endpoint] = {}
        
        # Clean old requests (older than 1 minute)
        if ip in self.endpoint_requests[endpoint]:
            self.endpoint_requests[endpoint][ip] = [
                ts for ts in self.endpoint_requests[endpoint][ip] 
                if now - ts < timedelta(minutes=1)
            ]
        
        # Get current request count
        current_count = len(self.endpoint_requests[endpoint].get(ip, []))
        
        # Calculate reset time (next minute boundary)
        reset_time = now.replace(second=0, microsecond=0) + timedelta(minutes=1)
        
        return current_count >= limit, current_count, limit, reset_time

    def add_request(self, ip: str, endpoint: str):
        """Add request to endpoint-specific tracking."""
        now = datetime.utcnow()
        
        if endpoint not in self.endpoint_requests:
            self.endpoint_requests[endpoint] = {}
        
        if ip not in self.endpoint_requests[endpoint]:
            self.endpoint_requests[endpoint][ip] = []
        
        self.endpoint_requests[endpoint][ip].append(now)

    def record_failed_attempt(self, ip: str):
        """Record failed authentication attempt and block IP if suspicious."""
        now = datetime.utcnow()
        suspicious_threshold = getattr(settings, 'SUSPICIOUS_IP_THRESHOLD', 5)
        
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = (1, now)
        else:
            count, first_attempt = self.failed_attempts[ip]
            if now - first_attempt < timedelta(minutes=5):
                if count + 1 >= suspicious_threshold:
                    self.block_ip(ip)
                else:
                    self.failed_attempts[ip] = (count + 1, first_attempt)
            else:
                # Reset counter after 5 minutes
                self.failed_attempts[ip] = (1, now)

    def block_ip(self, ip: str):
        """Block IP for suspicious activity."""
        block_duration_minutes = getattr(settings, 'IP_BLOCK_DURATION', 15)
        block_duration = timedelta(minutes=block_duration_minutes)
        self.blocked_ips[ip] = datetime.utcnow() + block_duration
        logger.warning(f"IP {ip} has been blocked for {block_duration_minutes} minutes due to suspicious activity")

class EnhancedRateLimitMiddleware(BaseHTTPMiddleware):
    """Enhanced rate limiting middleware with endpoint-specific limits and detailed error responses."""
    
    def __init__(self, app):
        super().__init__(app)
        self.rate_limiter = EnhancedRateLimiter()

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP, handling proxies."""
        # Check for forwarded IP headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        # Fallback to direct connection IP
        return request.client.host if request.client else "unknown"

    def _create_rate_limit_response(self, current_count: int, limit: int, reset_time: datetime, retry_after: int) -> Response:
        """Create standardized rate limit error response."""
        error_response = RateLimitErrorResponse(
            error=ErrorDetail(
                code=ErrorCode.RATE_LIMIT_EXCEEDED,
                message=f"Rate limit exceeded. Maximum {limit} requests per minute.",
                details=f"Current count: {current_count}/{limit}. Try again after {retry_after} seconds.",
                timestamp=datetime.utcnow()
            ),
            retry_after=retry_after,
            limit=limit,
            remaining=max(0, limit - current_count),
            reset_time=reset_time
        )
        
        response = Response(
            content=error_response.json(),
            media_type="application/json",
            status_code=429
        )
        response.headers["Retry-After"] = str(retry_after)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - current_count))
        response.headers["X-RateLimit-Reset"] = str(int(reset_time.timestamp()))
        
        return response

    def _create_ip_blocked_response(self, reset_time: datetime) -> Response:
        """Create IP blocked error response."""
        retry_after = int((reset_time - datetime.utcnow()).total_seconds())
        
        error_response = RateLimitErrorResponse(
            error=ErrorDetail(
                code=ErrorCode.IP_BLOCKED,
                message="IP temporarily blocked due to suspicious activity",
                details=f"IP will be unblocked in {retry_after} seconds",
                timestamp=datetime.utcnow()
            ),
            retry_after=retry_after,
            limit=0,
            remaining=0,
            reset_time=reset_time
        )
        
        response = Response(
            content=error_response.json(),
            media_type="application/json",
            status_code=403
        )
        response.headers["Retry-After"] = str(retry_after)
        
        return response

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip rate limiting for CORS preflight requests and health checks
        if request.method == "OPTIONS" or request.url.path in ["/health", "/docs", "/redoc"]:
            return await call_next(request)

        ip = self._get_client_ip(request)
        endpoint = request.url.path

        # Check rate limits
        is_limited, current_count, limit, reset_time = self.rate_limiter.is_rate_limited(ip, endpoint)
        
        if is_limited:
            if ip in self.rate_limiter.blocked_ips:
                # IP is blocked
                logger.warning(f"Blocked request from IP {ip} to {endpoint}")
                return self._create_ip_blocked_response(reset_time)
            else:
                # Rate limit exceeded
                retry_after = 60  # 1 minute
                logger.warning(f"Rate limit exceeded for IP {ip} on {endpoint}: {current_count}/{limit}")
                return self._create_rate_limit_response(current_count, limit, reset_time, retry_after)

        # Add request to counter
        self.rate_limiter.add_request(ip, endpoint)

        # Process request
        response = await call_next(request)

        # Record failed authentication attempts for auth endpoints
        if (response.status_code in [401, 403] and 
            endpoint.startswith("/auth/") and 
            endpoint in ["/auth/verify", "/auth/challenge"]):
            self.rate_limiter.record_failed_attempt(ip)
            logger.info(f"Recorded failed auth attempt from IP {ip} on {endpoint}")

        # Add rate limit headers to successful responses
        if response.status_code < 400:
            response.headers["X-RateLimit-Limit"] = str(limit)
            response.headers["X-RateLimit-Remaining"] = str(max(0, limit - current_count - 1))
            response.headers["X-RateLimit-Reset"] = str(int(reset_time.timestamp()))

        return response