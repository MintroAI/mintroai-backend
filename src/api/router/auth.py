"""
Authentication API router - delegates to the enhanced auth controller.
"""

from fastapi import APIRouter
from src.api.controller.auth.auth_controller import router as auth_controller_router, init_protocols

# Re-export the controller router
router = auth_controller_router

# Re-export init function for app startup
__all__ = ['router', 'init_protocols']