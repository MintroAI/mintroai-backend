from datetime import datetime
from typing import Optional, Dict, Any

from fastapi import Request, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError

from src.infra.config.settings import settings
from src.core.logger.logger import logger

class CustomHTTPBearer(HTTPBearer):
    async def __call__(self, request: Request) -> Optional[str]:
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                raise HTTPException(status_code=401, detail="Not authenticated")

            scheme, credentials = auth_header.split()
            if scheme.lower() != "bearer":
                raise HTTPException(status_code=401, detail="Invalid authentication scheme")

            if not self.verify_jwt(credentials):
                raise HTTPException(status_code=401, detail="Invalid token or expired token")

            return credentials

        except ValueError:
            raise HTTPException(status_code=401, detail="Invalid authorization header")
        except HTTPException as e:
            logger.error(f"Authentication error: {str(e.detail)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected authentication error: {str(e)}")
            raise HTTPException(status_code=401, detail="Authentication failed")

    def verify_jwt(self, jwt_token: str) -> bool:
        try:
            payload = jwt.decode(
                jwt_token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
            # Check if token has expired
            exp = payload.get("exp")
            if exp:
                if datetime.utcfromtimestamp(exp) < datetime.utcnow():
                    raise HTTPException(
                        status_code=401,
                        detail="Token has expired. Please refresh your token"
                    )
            return True
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=401,
                detail="Token has expired. Please refresh your token"
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=403,
                detail="Invalid signature"
            )
        except Exception as e:
            logger.error(f"JWT verification error: {str(e)}")
            return False