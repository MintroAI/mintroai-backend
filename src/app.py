import json
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.infra.config.settings import settings
from src.core.logger.logger import logger
from src.api.router import health, protected, mock_endpoint, auth, chat, funding, contract
from src.api.middleware.security.rate_limiter import RateLimitMiddleware
from src.api.middleware.security.audit_logger import AuditLoggingMiddleware
from src.api.middleware.logging.request_logging import RequestLoggingMiddleware

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        description="""
# 🚀 MintroAI Blockchain Services API

A comprehensive platform for blockchain authentication, smart contract generation, and DeFi services.

## 🔐 **Authentication Services**
Multi-protocol wallet authentication supporting EVM and NEAR Protocol.

### Supported Protocols
- **EVM**: Ethereum, Polygon, BSC, Arbitrum, Optimism
- **NEAR**: NEAR Protocol blockchain

### Auth Flow
1. **Create Challenge** → Get unique message to sign
2. **Sign Message** → Use your wallet to sign
3. **Verify Signature** → Get JWT tokens
4. **Access Protected Endpoints** → Use Bearer token

## 📜 **Smart Contract Services**
End-to-end smart contract development and deployment.

### Contract Generation
- **Token Contracts**: ERC20/NEP-141 with customizable features
- **Vesting Contracts**: Token vesting with cliff and release schedules
- **Custom Parameters**: Mintable, burnable, pausable, anti-bot features

### Contract Compilation
- **Solidity Compilation**: Generate bytecode and ABI
- **Cross-chain Support**: Multiple blockchain targets
- **Optimization**: Gas-optimized contract bytecode

### Contract Pricing
- **Deployment Costs**: Real-time gas estimation
- **Signature Generation**: Ready-to-deploy transaction data
- **Multi-chain Support**: Different networks and gas tokens

## 💰 **DeFi Services**
- **NEAR Chain Signatures**: Cross-chain transaction funding
- **Multi-chain Wallet**: Unified wallet management

## 🛡️ **Security Features**
- JWT-based authentication
- Rate limiting and IP blocking
- Audit logging and monitoring
- Input validation and sanitization

## 📡 **Real-time Features**
- WebSocket connections for live updates
- Chat integration with AI assistance
- Real-time contract compilation status

## 🚀 **Quick Start**

### Authentication
```bash
# 1. Create challenge
curl -X POST "/api/v1/auth/challenge" \\
     -H "Content-Type: application/json" \\
     -d '{"wallet_address": "0x...", "protocol": "evm"}'

# 2. Verify signature
curl -X POST "/api/v1/auth/verify" \\
     -H "Content-Type: application/json" \\
     -d '{"wallet_address": "0x...", "signature": "0x...", "protocol": "evm"}'
```

### Smart Contracts
```bash
# Generate contract
curl -X POST "/api/v1/generate-contract" \\
     -H "Authorization: Bearer <token>" \\
     -H "Content-Type: application/json" \\
     -d '{"contractType": "token", "tokenName": "MyToken", ...}'

# Compile contract  
curl -X POST "/api/v1/compile-contract" \\
     -H "Authorization: Bearer <token>" \\
     -H "Content-Type: application/json" \\
     -d '{"chatId": "your-chat-id"}'

# Get deployment price
curl -X POST "/api/v1/price-contract" \\
     -H "Authorization: Bearer <token>" \\
     -H "Content-Type: application/json" \\
     -d '{"contractData": {...}, "bytecode": "0x..."}'
```
        """,
        version=settings.APP_VERSION,
        docs_url="/",
        redoc_url="/redoc",
        contact={
            "name": "MintroAI Team",
            "url": "https://mintroai.com",
            "email": "support@mintroai.com"
        },
        license_info={
            "name": "MIT License",
            "url": "https://opensource.org/licenses/MIT"
        },
        servers=[
            {
                "url": "http://localhost:8000",
                "description": "Development server"
            },
            {
                "url": "https://api.mintroai.com",
                "description": "Production server"
            }
        ]
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
        max_age=600,  # 10 minutes
    )

    # Request logging middleware (should be first to catch all requests)
    app.add_middleware(RequestLoggingMiddleware)

    # Audit logging middleware
    app.add_middleware(AuditLoggingMiddleware)

    # Rate limiting middleware
    app.add_middleware(RateLimitMiddleware)

    # Include routers
    from src.api.router import websocket, config, webhook
    
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(chat.router, prefix="/api/v1")
    app.include_router(funding.router)  # Funding router uses /api/v1 prefix
    app.include_router(contract.router)  # Contract router with /api/v1/contract prefix
    app.include_router(protected.router, prefix="/api/v1")
    app.include_router(mock_endpoint.router, prefix="/api/v1")
    
    # Include Node.js compatible endpoints (without prefix)
    app.include_router(config.router)  # /config endpoints
    app.include_router(webhook.router)  # /webhook endpoint
    app.include_router(websocket.router)  # /ws endpoint

    # Initialize WebSocket manager
    from src.core.service.websocket.manager import ConnectionManager
    app.state.ws_manager = ConnectionManager()
    
    # Initialize configurations store - exactly like Node.js
    app.state.configurations = {}
    
    @app.on_event("startup")
    async def startup_event():
        logger.info(json.dumps({
            "message": "Starting API Gateway",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION
        }))
        
        # Initialize protocol verifiers
        try:
            from src.api.router.auth import init_protocols
            await init_protocols()
        except Exception as e:
            logger.error(f"Failed to initialize protocols on startup: {str(e)}")
        
        # Initialize chat services
        try:
            from src.api.controller.chat.chat_controller import init_chat_services
            await init_chat_services()
        except Exception as e:
            logger.error(f"Failed to initialize chat services on startup: {str(e)}")

    @app.on_event("shutdown")
    async def shutdown_event():
        logger.info(json.dumps({
            "message": "Shutting down API Gateway",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION
        }))

    return app