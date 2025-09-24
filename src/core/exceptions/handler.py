"""
Centralized error handling system for high-performance applications.
Provides consistent error responses, logging, and HTTP status codes across all services.
"""

import traceback
from typing import Dict, Any, Optional, Union
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from datetime import datetime

from src.core.logger.logger import get_logger
from src.infra.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()


class ServiceErrorCode:
    """Standard error codes for services"""
    
    # Validation
    INVALID_INPUT = "INVALID_INPUT"
    MISSING_FIELD = "MISSING_FIELD"
    INVALID_FORMAT = "INVALID_FORMAT"
    
    # Authentication
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    EXPIRED_CHALLENGE = "EXPIRED_CHALLENGE"
    CHALLENGE_NOT_FOUND = "CHALLENGE_NOT_FOUND"
    INVALID_TOKEN = "INVALID_TOKEN"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    
    # Protocol
    UNSUPPORTED_PROTOCOL = "UNSUPPORTED_PROTOCOL" 
    INVALID_ADDRESS = "INVALID_ADDRESS"
    RPC_ERROR = "RPC_ERROR"
    
    # Rate Limiting
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    IP_BLOCKED = "IP_BLOCKED"
    
    # Business Logic
    INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
    NETWORK_ERROR = "NETWORK_ERROR"
    GAS_ESTIMATION_ERROR = "GAS_ESTIMATION_ERROR"
    TRANSACTION_FAILED = "TRANSACTION_FAILED"
    
    # System
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    CONNECTION_FAILED = "CONNECTION_FAILED"


class ServiceError(Exception):
    """
    Standardized service error for internal use.
    Gets converted to proper HTTP response by error handler.
    """
    
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        self.context = context or {}
        super().__init__(message)


class ErrorResponseBuilder:
    """Builds standardized error responses"""
    
    @staticmethod
    def build_error_response(
        error_code: str,
        message: str,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Build standardized error response"""
        
        response = {
            "success": False,
            "error": {
                "code": error_code,
                "message": message,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        }
        
        if details:
            response["error"]["details"] = details
            
        if request_id:
            response["error"]["request_id"] = request_id
            
        return response
    
    @staticmethod
    def build_validation_error_response(
        validation_errors: list,
        request_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Build validation error response"""
        
        return ErrorResponseBuilder.build_error_response(
            error_code=ServiceErrorCode.INVALID_INPUT,
            message="Validation failed",
            status_code=422,
            details={
                "validation_errors": validation_errors
            },
            request_id=request_id
        )


class GlobalErrorHandler:
    """Global error handler for all application errors"""
    
    @staticmethod
    async def service_error_handler(request: Request, exc: ServiceError) -> JSONResponse:
        """Handle ServiceError exceptions"""
        
        request_id = request.headers.get("X-Request-ID", "unknown")
        
        # Log error with context
        logger.error(
            f"Service error: {exc.code}",
            extra={
                "error_code": exc.code,
                "message": exc.message,
                "status_code": exc.status_code,
                "details": exc.details,
                "context": exc.context,
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method
            }
        )
        
        response = ErrorResponseBuilder.build_error_response(
            error_code=exc.code,
            message=exc.message,
            status_code=exc.status_code,
            details=exc.details,
            request_id=request_id
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content=response
        )
    
    @staticmethod
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        """Handle HTTPException with standardized format"""
        
        request_id = request.headers.get("X-Request-ID", "unknown")
        
        # Determine error code based on status
        if exc.status_code == 401:
            error_code = ServiceErrorCode.INVALID_TOKEN
        elif exc.status_code == 403:
            error_code = ServiceErrorCode.RATE_LIMIT_EXCEEDED
        elif exc.status_code == 404:
            error_code = ServiceErrorCode.CHALLENGE_NOT_FOUND
        elif exc.status_code == 422:
            error_code = ServiceErrorCode.INVALID_INPUT
        elif exc.status_code >= 500:
            error_code = ServiceErrorCode.INTERNAL_ERROR
        else:
            error_code = ServiceErrorCode.INTERNAL_ERROR
        
        logger.warning(
            f"HTTP exception: {exc.status_code}",
            extra={
                "status_code": exc.status_code,
                "detail": exc.detail,
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method
            }
        )
        
        response = ErrorResponseBuilder.build_error_response(
            error_code=error_code,
            message=str(exc.detail),
            status_code=exc.status_code,
            request_id=request_id
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content=response
        )
    
    @staticmethod
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        """Handle Pydantic validation errors"""
        
        request_id = request.headers.get("X-Request-ID", "unknown")
        
        validation_errors = []
        for error in exc.errors():
            field = '.'.join(str(loc) for loc in error['loc'])
            validation_errors.append({
                'field': field,
                'message': error['msg'],
                'input': error.get('input')
            })
        
        logger.warning(
            f"Validation error: {len(validation_errors)} errors",
            extra={
                "validation_errors": validation_errors,
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method
            }
        )
        
        response = ErrorResponseBuilder.build_validation_error_response(
            validation_errors=validation_errors,
            request_id=request_id
        )
        
        return JSONResponse(
            status_code=422,
            content=response
        )
    
    @staticmethod
    async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle unexpected exceptions"""
        
        request_id = request.headers.get("X-Request-ID", "unknown")
        
        # Log full traceback for debugging
        logger.error(
            f"Unexpected error: {type(exc).__name__}",
            extra={
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "traceback": traceback.format_exc()
            },
            exc_info=True
        )
        
        # Never expose internal errors in production
        if settings.DEBUG:
            message = f"Internal error: {str(exc)}"
            details = {"traceback": traceback.format_exc()}
        else:
            message = "An unexpected error occurred. Please try again."
            details = {}
        
        response = ErrorResponseBuilder.build_error_response(
            error_code=ServiceErrorCode.INTERNAL_ERROR,
            message=message,
            status_code=500,
            details=details,
            request_id=request_id
        )
        
        return JSONResponse(
            status_code=500,
            content=response
        )
