"""
Chat API router - delegates to chat controller
"""

from src.api.controller.chat.chat_controller import router

# Re-export the controller router
__all__ = ['router']
