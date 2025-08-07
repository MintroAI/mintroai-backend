# 🚀 MintroAI Backend

A high-performance, multi-blockchain authentication backend service built with FastAPI. This service provides secure wallet-based authentication for both EVM (Ethereum) and NEAR Protocol wallets, along with JWT token management and comprehensive security features.

## ✨ Features

- **Multi-Blockchain Support**: EVM (Ethereum, Polygon, etc.) and NEAR Protocol wallet authentication
- **Secure Authentication**: Challenge-response authentication with cryptographic signature verification
- **JWT Token Management**: Access/refresh token system with blacklisting support
- **Rate Limiting & Security**: IP-based rate limiting, request throttling, and security headers
- **Structured Logging**: Comprehensive logging with correlation IDs for request tracking
- **Redis Integration**: High-performance caching for challenges, sessions, and security data
- **Test-Driven Development**: Comprehensive test suite with >90% coverage
- **Production Ready**: Docker support, environment configuration, and monitoring

## 🏗️ Architecture

```
src/
├── api/                    # API layer
│   ├── middleware/         # Authentication, security, logging middleware
│   └── router/            # API endpoints
├── core/                   # Business logic
│   ├── service/           # Domain services
│   │   └── auth/          # Authentication services
│   │       ├── protocols/ # Multi-blockchain protocol implementations
│   │       ├── models/    # Data models
│   │       └── cache/     # Redis caching layer
│   ├── exceptions/        # Custom exceptions
│   └── logger/           # Structured logging
└── infra/                 # Infrastructure
    └── config/           # Settings and configuration
```

## 🚦 Getting Started

### Prerequisites

- Python 3.11+
- Redis Server
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/mintroai-backend.git
   cd mintroai-backend
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Start Redis server**
   ```bash
   redis-server
   ```

6. **Run the application**
   ```bash
   python main.py
   ```

The API will be available at `http://localhost:8000`

## 📖 API Documentation

Once the server is running, visit:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### Key Endpoints

- `GET /health` - Health check endpoint
- `POST /auth/challenge` - Request authentication challenge
- `POST /auth/verify` - Verify wallet signature and get JWT tokens
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Logout and blacklist tokens

## 🔧 Configuration

Key environment variables:

```env
# Server Configuration
HOST=0.0.0.0
PORT=8000
DEBUG=False

# Security
JWT_SECRET_KEY=your-super-secret-key
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_DB=0

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_SECONDS=60

# Blockchain Configuration
SUPPORTED_PROTOCOLS=["evm", "near"]
DEFAULT_PROTOCOL=evm

# NEAR Protocol
NEAR_NETWORK_ID=testnet
NEAR_RPC_URLS=["https://rpc.testnet.near.org"]
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=src

# Run specific test categories
python -m pytest tests/unit/          # Unit tests
python -m pytest tests/integration/   # Integration tests
python -m pytest tests/contract/      # Contract tests
```

## 🚀 Deployment

### Docker Deployment

```bash
# Build image
docker build -t mintroai-backend .

# Run container
docker run -p 8000:8000 --env-file .env mintroai-backend
```

### Production Considerations

- Use a production WSGI server (e.g., Gunicorn with Uvicorn workers)
- Set up proper Redis clustering for high availability
- Configure proper logging aggregation
- Set up monitoring and alerting
- Use environment-specific configuration files
- Enable HTTPS with proper SSL certificates

## 🔐 Security Features

- **Wallet-Based Authentication**: No passwords, only cryptographic signatures
- **Challenge-Response Protocol**: Prevents replay attacks
- **JWT Token Security**: Short-lived access tokens with refresh mechanism
- **Rate Limiting**: Prevents abuse and DDoS attacks
- **IP Blocking**: Automatic blocking of malicious IPs
- **Request Validation**: Comprehensive input validation and sanitization
- **CORS Configuration**: Proper cross-origin resource sharing setup
- **Security Headers**: HSTS, CSP, and other security headers

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following our coding standards
4. Add tests for new functionality
5. Ensure all tests pass (`python -m pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Write comprehensive tests for new features
- Update documentation for API changes
- Use type hints for better code clarity
- Follow the existing project structure

## 📊 Monitoring & Observability

The application includes:
- Structured JSON logging with correlation IDs
- Health check endpoints for load balancers
- Request/response timing metrics
- Error rate tracking
- Redis connection monitoring

## 🔄 Blockchain Protocol Support

### EVM Chains (Ethereum, Polygon, etc.)
- Ethereum-style signature verification
- Support for MetaMask and other EVM wallets
- Configurable chain IDs

### NEAR Protocol
- Ed25519 signature verification
- Support for NEAR Wallet and other NEAR-compatible wallets
- Testnet and mainnet support

### Adding New Protocols
The architecture supports easy addition of new blockchain protocols by implementing the `WalletVerifier` interface.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the `/docs` endpoint when running the server
- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Join our community discussions for questions and ideas

## 🏷️ Version History

- **v1.0.0** - Initial release with EVM and NEAR protocol support
- **v0.9.0** - Beta release with core authentication features
- **v0.8.0** - Alpha release with basic wallet authentication

---

**Built with ❤️ by the MintroAI Team**