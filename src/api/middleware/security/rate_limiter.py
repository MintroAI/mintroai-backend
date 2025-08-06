from datetime import datetime, timedelta
from typing import Dict, Tuple
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from src.infra.config.settings import settings
from src.core.logger.logger import logger

class RateLimiter:
    def __init__(self):
        self.requests: Dict[str, list] = {}  # IP -> List of request timestamps
        self.blocked_ips: Dict[str, datetime] = {}  # IP -> Unblock time
        self.failed_attempts: Dict[str, Tuple[int, datetime]] = {}  # IP -> (count, first_attempt)

    def is_rate_limited(self, ip: str) -> bool:
        now = datetime.utcnow()
        
        # Clean old requests
        if ip in self.requests:
            self.requests[ip] = [ts for ts in self.requests[ip] 
                               if now - ts < timedelta(minutes=1)]
        
        # Check if IP is blocked
        if ip in self.blocked_ips:
            if now < self.blocked_ips[ip]:
                return True
            else:
                del self.blocked_ips[ip]
        
        # Check rate limit
        request_count = len(self.requests.get(ip, []))
        return request_count >= settings.RATE_LIMIT_MAX_REQUESTS

    def add_request(self, ip: str):
        now = datetime.utcnow()
        if ip not in self.requests:
            self.requests[ip] = []
        self.requests[ip].append(now)

    def record_failed_attempt(self, ip: str):
        now = datetime.utcnow()
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = (1, now)
        else:
            count, first_attempt = self.failed_attempts[ip]
            if now - first_attempt < timedelta(minutes=5):
                if count + 1 >= settings.SUSPICIOUS_IP_THRESHOLD:
                    self.block_ip(ip)
                else:
                    self.failed_attempts[ip] = (count + 1, first_attempt)
            else:
                self.failed_attempts[ip] = (1, now)

    def block_ip(self, ip: str):
        block_duration = timedelta(minutes=settings.IP_BLOCK_DURATION)
        self.blocked_ips[ip] = datetime.utcnow() + block_duration
        logger.warning(f"IP {ip} has been blocked for suspicious activity")

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.rate_limiter = RateLimiter()

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip rate limiting for CORS preflight requests
        if request.method == "OPTIONS":
            return await call_next(request)

        ip = request.client.host

        # Check if IP is blocked
        if ip in self.rate_limiter.blocked_ips:
            if datetime.utcnow() < self.rate_limiter.blocked_ips[ip]:
                logger.warning(f"Blocked request from banned IP: {ip}")
                raise HTTPException(
                    status_code=403,
                    detail="IP has been temporarily blocked due to suspicious activity"
                )
            else:
                del self.rate_limiter.blocked_ips[ip]

        # Check rate limit
        if self.rate_limiter.is_rate_limited(ip):
            retry_after = 60  # 1 minute
            logger.warning(f"Rate limit exceeded for IP: {ip}")
            response = Response(
                content='{"detail": "Too many requests"}',
                media_type="application/json",
                status_code=429
            )
            response.headers["Retry-After"] = str(retry_after)
            return response

        # Add request to counter
        self.rate_limiter.add_request(ip)

        # Process request
        response = await call_next(request)

        # Record failed authentication attempts
        if response.status_code in [401, 403] and "test/wallet-verify" in request.url.path:
            self.rate_limiter.record_failed_attempt(ip)

        return response