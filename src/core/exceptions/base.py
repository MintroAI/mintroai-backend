from typing import Any, Dict, Optional
from fastapi import HTTPException, status


class BaseAPIException(HTTPException):
    def __init__(
        self,
        status_code: int,
        message: str,
        detail: Optional[Any] = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=detail)
        self.message = message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "message": self.message,
            "detail": self.detail,
        }


class NotFoundError(BaseAPIException):
    def __init__(self, message: str = "Resource not found", detail: Optional[Any] = None):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            message=message,
            detail=detail,
        )


class ValidationError(BaseAPIException):
    def __init__(self, message: str = "Validation error", detail: Optional[Any] = None):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            message=message,
            detail=detail,
        )


class UnauthorizedError(BaseAPIException):
    def __init__(self, message: str = "Unauthorized", detail: Optional[Any] = None):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            message=message,
            detail=detail,
        )