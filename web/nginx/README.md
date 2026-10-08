# Nginx Configuration

The nginx front end used by `web/docker-compose.prod.yml` (the web console image
alone behind nginx). The supported OpenCTEM deployment uses the platform gateway
instead (`api/deploy/gateway`, see
[docs.openctem.io/install](https://docs.openctem.io/install/)).

## SSL Certificates

For production, you need SSL certificates. Here are your options:

### Option 1: Let's Encrypt (Free, Recommended)

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate (automatic)
sudo certbot --nginx -d ctem.example.com

# Certificates will be placed in:
# /etc/letsencrypt/live/ctem.example.com/fullchain.pem
# /etc/letsencrypt/live/ctem.example.com/privkey.pem

# Update nginx.conf to use these paths
```

### Option 2: Self-Signed Certificate (Development Only)

```bash
# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# WARNING: Self-signed certificates will show browser warnings
# Only use for local development
```

### Option 3: Certificate from your CA

1. Obtain a certificate from your certificate authority
2. Place certificate files in `nginx/ssl/`
3. Update nginx.conf paths

## Configuration

1. **Edit nginx.conf:**
   - Replace the placeholder `server_name your-domain.com` with your domain
   - Update SSL certificate paths
   - Adjust rate limiting if needed

2. **Test configuration:**
   ```bash
   docker compose -f docker-compose.prod.yml exec nginx nginx -t
   ```

3. **Reload Nginx:**
   ```bash
   docker compose -f docker-compose.prod.yml exec nginx nginx -s reload
   ```

## Directory Structure

```
nginx/
├── nginx.conf       # Main Nginx configuration
├── ssl/            # SSL certificates directory
│   ├── cert.pem    # SSL certificate (you provide)
│   └── key.pem     # SSL private key (you provide)
└── README.md       # This file
```

## Security Notes

- Never commit SSL private keys to Git (.gitignore already configured)
- Rotate certificates before expiry
- Use strong SSL protocols (TLSv1.2, TLSv1.3)
- Enable HSTS (already configured)
