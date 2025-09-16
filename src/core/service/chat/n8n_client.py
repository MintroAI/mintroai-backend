"""
n8n workflow client for chat integration
"""

import httpx
import json
from typing import Dict, Any, Optional
from datetime import datetime

from src.core.service.chat.models.chat import ChatRequest, ChatMode, UserContext
from src.core.logger.logger import get_logger
from src.infra.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()


class N8nWorkflowConfig:
    """Configuration for n8n workflows"""
    
    def __init__(self):
        self.workflows = {
            ChatMode.TOKEN: {
                "url": settings.N8N_TOKEN_WORKFLOW_URL or "https://barisarya.app.n8n.cloud/webhook/b8bce491-1fee-470c-aa7a-20a5e619fa51",
                "timeout": 25,
                "url_pattern": "{base_url}/{session_id}",
                "body_format": "action_based"
            },
            ChatMode.VESTING: {
                "url": settings.N8N_VESTING_WORKFLOW_URL or "https://mintro.app.n8n.cloud/webhook/9a30de38-7fbc-4de1-bac3-69f5b627304f",
                "timeout": 25,
                "url_pattern": "{base_url}/{session_id}",
                "body_format": "action_based"
            },
            ChatMode.GENERAL: {
                "url": settings.N8N_GENERAL_WORKFLOW_URL or "https://chaingpt-proxy-production.up.railway.app/chat/general",
                "timeout": 75,
                "url_pattern": "{base_url}",
                "body_format": "direct"
            }
        }


class N8nClient:
    """Client for communicating with n8n workflows"""
    
    def __init__(self):
        self.config = N8nWorkflowConfig()
        self.logger = logger
        
    def _build_url(self, mode: ChatMode, session_id: str) -> str:
        """Build URL based on workflow configuration"""
        workflow = self.config.workflows[mode]
        base_url = workflow["url"]
        
        if workflow["url_pattern"] == "{base_url}/{session_id}":
            return f"{base_url}/{session_id}"
        return base_url
    
    def _build_request_body(
        self, 
        request: ChatRequest, 
        user_context: Optional[UserContext] = None
    ) -> Dict[str, Any]:
        """Build request body based on workflow format"""
        workflow = self.config.workflows[request.mode]
        
        if workflow["body_format"] == "action_based":
            body = {
                "sessionId": request.sessionId,
                "action": "sendMessage",
                "chatInput": request.chatInput
            }
        else:  # direct format
            body = {
                "sessionId": request.sessionId,
                "chatInput": request.chatInput,
                "mode": request.mode.value
            }
        
        # Add user context if available
        if user_context:
            body["userContext"] = {
                "walletAddress": user_context.wallet_address,
                "isAuthenticated": user_context.is_authenticated,
                "userType": user_context.user_type,
                "walletType": user_context.wallet_type
            }
        
        return body
    
    async def send_to_n8n(
        self, 
        request: ChatRequest, 
        user_context: Optional[UserContext] = None
    ) -> Dict[str, Any]:
        """
        Send request to appropriate n8n workflow based on mode
        
        Args:
            request: Chat request with session ID, input, and mode
            user_context: Optional user context for authenticated users
            
        Returns:
            Dict containing n8n response
            
        Raises:
            HTTPException: On timeout or connection errors
        """
        workflow = self.config.workflows[request.mode]
        url = self._build_url(request.mode, request.sessionId)
        body = self._build_request_body(request, user_context)
        
        self.logger.info(
            f"Sending request to n8n workflow",
            extra={
                "mode": request.mode.value,
                "session_id": request.sessionId,
                "url": url,
                "timeout": workflow["timeout"]
            }
        )
        
        async with httpx.AsyncClient() as client:
            try:
                start_time = datetime.utcnow()
                
                response = await client.post(
                    url,
                    json=body,
                    headers={"Content-Type": "application/json"},
                    timeout=workflow["timeout"]
                )
                
                duration = (datetime.utcnow() - start_time).total_seconds()
                
                self.logger.info(
                    f"n8n workflow response received",
                    extra={
                        "mode": request.mode.value,
                        "session_id": request.sessionId,
                        "status_code": response.status_code,
                        "duration_seconds": duration
                    }
                )
                
                # Handle response
                if response.status_code != 200:
                    self.logger.error(
                        f"n8n workflow returned error status",
                        extra={
                            "status_code": response.status_code,
                            "response_text": response.text[:500]  # First 500 chars
                        }
                    )
                    return {
                        "error": f"n8n workflow error: {response.status_code}",
                        "details": response.text[:500]
                    }
                
                # Parse response
                content_type = response.headers.get('content-type', '')
                if content_type.startswith('application/json'):
                    return response.json()
                else:
                    # Try to parse as JSON anyway
                    text = response.text
                    try:
                        return json.loads(text)
                    except json.JSONDecodeError:
                        self.logger.warning(
                            f"Non-JSON response from n8n workflow",
                            extra={
                                "mode": request.mode.value,
                                "content_type": content_type,
                                "response_preview": text[:200]
                            }
                        )
                        # Return the text as output
                        return {"output": text, "raw": text}
                        
            except httpx.TimeoutException:
                self.logger.error(
                    f"n8n workflow timeout",
                    extra={
                        "mode": request.mode.value,
                        "session_id": request.sessionId,
                        "timeout_seconds": workflow["timeout"]
                    }
                )
                raise TimeoutError(
                    f"Request timeout - {request.mode.value} workflow took longer than {workflow['timeout']} seconds"
                )
                
            except httpx.RequestError as e:
                self.logger.error(
                    f"n8n workflow connection error",
                    extra={
                        "mode": request.mode.value,
                        "session_id": request.sessionId,
                        "error": str(e)
                    }
                )
                raise ConnectionError(
                    f"Failed to connect to n8n workflow: {str(e)}"
                )
                
            except Exception as e:
                self.logger.error(
                    f"Unexpected error in n8n client",
                    extra={
                        "mode": request.mode.value,
                        "session_id": request.sessionId,
                        "error": str(e)
                    }
                )
                raise
