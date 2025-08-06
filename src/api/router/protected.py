from fastapi import APIRouter, Depends, HTTPException
from jose import jwt

from src.api.middleware.authentication.jwt_bearer import CustomHTTPBearer
from src.infra.config.settings import settings
from src.core.logger.logger import logger

router = APIRouter()

@router.get("/protected", dependencies=[Depends(CustomHTTPBearer())])
async def protected_route(token: str = Depends(CustomHTTPBearer())):
    """
    Protected endpoint that requires valid JWT token
    Returns user information from the token
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        logger.info(f"Authenticated access to protected endpoint by {payload.get('sub')}")
        return {
            "email": payload.get("sub"),
            "scope": payload.get("scope")
        }
    except Exception as e:
        logger.error(f"Error processing token: {str(e)}")
        raise HTTPException(status_code=401, detail="Could not process token")