# SSL Certificate Setup

Place your SSL certificate files in this directory:

## Required Files:
- `server.crt` - SSL certificate file
- `server.key` - Private key file

## Quick Setup Options:

### 1. Self-Signed Certificate (Development/Testing)
```bash
# Generate self-signed cert (valid for 365 days)
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=US/ST=State/L=City/O=MintroAI/CN=localhost"

# Set permissions
chmod 600 server.key
chmod 644 server.crt
```

### 2. Let's Encrypt Certificate (Production)
```bash
# Install certbot first, then:
sudo certbot certonly --standalone -d your-domain.com

# Copy to project
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem server.crt
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem server.key
sudo chmod 644 server.crt
sudo chmod 600 server.key
```

### 3. Existing Certificate
Just copy your existing certificate files to this directory with the correct names.

## After Adding Certificates:
```bash
# Restart the services
docker-compose down
docker-compose up -d

# Test HTTPS
curl -k https://localhost/api/v1/health
```
