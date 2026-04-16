# detekta-backend — Deployment Guide

This guide covers production deployment of the **Detekta** backend on a Linux VPS (Ubuntu 22.04 LTS recommended). It covers bare-metal setup, Docker Compose, Nginx reverse proxy, SSL, and basic hardening.

---

## Table of Contents

- [Requirements](#requirements)
- [Server Preparation](#server-preparation)
- [MongoDB Setup](#mongodb-setup)
- [Backend Setup](#backend-setup)
- [Environment Configuration](#environment-configuration)
- [Running with Gunicorn + Uvicorn Workers](#running-with-gunicorn--uvicorn-workers)
- [Systemd Service](#systemd-service)
- [Nginx Reverse Proxy](#nginx-reverse-proxy)
- [SSL — Let's Encrypt](#ssl--lets-encrypt)
- [MobSF (Mobile Audits)](#mobsf-mobile-audits)
- [Docker Compose (All-in-One)](#docker-compose-all-in-one)
- [Health Check & Smoke Test](#health-check--smoke-test)
- [Updating the Application](#updating-the-application)
- [Security Hardening](#security-hardening)
- [Monitoring & Logs](#monitoring--logs)
- [Troubleshooting](#troubleshooting)

---

## Requirements

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 2 GB | 4 GB |
| Disk | 20 GB SSD | 40 GB SSD |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| Python | 3.11 | 3.11+ |
| MongoDB | 6.0 | 7.0 |
| Docker | 20.10+ | latest |
| Open ports | 80, 443 | 80, 443 |

> MobSF requires an additional 2 GB RAM and ~5 GB disk.

---

## Server Preparation

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install base dependencies
sudo apt install -y \
    python3.11 python3.11-venv python3.11-dev \
    build-essential \
    nmap \
    git \
    curl \
    nginx \
    certbot python3-certbot-nginx \
    libpango-1.0-0 libpangoft2-1.0-0 libffi-dev \
    libcairo2 libpangocairo-1.0-0

# Install Docker (for MobSF)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

### Create a dedicated user

```bash
sudo useradd -m -s /bin/bash detekta
sudo -u detekta -i
```

---

## MongoDB Setup

### Option A — Install locally

```bash
# Import MongoDB GPG key
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc \
  | sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor

echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] \
  https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" \
  | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

sudo apt update && sudo apt install -y mongodb-org

sudo systemctl enable --now mongod
```

Create a dedicated database user:

```bash
mongosh
```

```js
use detekta
db.createUser({
  user: "detekta_user",
  pwd: "STRONG_PASSWORD_HERE",
  roles: [{ role: "readWrite", db: "detekta" }]
})
exit
```

Then update `.env`:
```env
MONGO_URL=mongodb://detekta_user:STRONG_PASSWORD_HERE@127.0.0.1:27017/detekta?authSource=detekta
```

### Option B — MongoDB Atlas (managed cloud)

```env
MONGO_URL=mongodb+srv://<user>:<pass>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
DB_NAME=detekta
```

---

## Backend Setup

```bash
# Switch to the detekta user
sudo -u detekta -i

# Clone the repository
git clone <repo-url> ~/detekta
cd ~/detekta/detekta-backend

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Prepare upload directory
mkdir -p /var/detekta/uploads
```

---

## Environment Configuration

```bash
cp .env.example .env
nano .env
```

Populate every required field:

```env
APP_ENV=production

# Generate with: openssl rand -hex 32
JWT_SECRET=your_64_char_hex_secret

# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY=your_fernet_key_here

MONGO_URL=mongodb://detekta_user:STRONG_PASSWORD@127.0.0.1:27017/detekta?authSource=detekta
DB_NAME=detekta

AI_LLM_KEY=sk-ant-api03-...
CLAUDE_MODEL=claude-sonnet-4-5-20250929

# Your actual domain(s)
CORS_ORIGINS=https://app.yourdomain.com

UPLOAD_DIR=/var/detekta/uploads
MAX_FILE_SIZE_MB=200
DEFAULT_LANGUAGE=en

# If running MobSF locally
MOBSF_URL=http://localhost:8888
```

Set restrictive permissions on `.env`:

```bash
chmod 600 .env
```

---

## Running with Gunicorn + Uvicorn Workers

Gunicorn manages multiple Uvicorn worker processes for production resilience:

```bash
source ~/detekta/detekta-backend/venv/bin/activate

gunicorn server:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 127.0.0.1:8001 \
  --timeout 120 \
  --access-logfile /var/log/detekta/gunicorn-access.log \
  --error-logfile /var/log/detekta/gunicorn-error.log
```

> **Worker count guideline:** `(2 × CPU cores) + 1`. For a 2-vCPU server use `--workers 5`.

Create log directory first:

```bash
sudo mkdir -p /var/log/detekta
sudo chown detekta:detekta /var/log/detekta
```

---

## Systemd Service

Create a service unit so the backend starts automatically and restarts on failure:

```bash
sudo nano /etc/systemd/system/detekta-backend.service
```

```ini
[Unit]
Description=Detekta Backend (FastAPI + Gunicorn)
After=network.target mongod.service
Requires=mongod.service

[Service]
User=detekta
Group=detekta
WorkingDirectory=/home/detekta/detekta/detekta-backend
EnvironmentFile=/home/detekta/detekta/detekta-backend/.env
ExecStart=/home/detekta/detekta/detekta-backend/venv/bin/gunicorn server:app \
    --workers 4 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 127.0.0.1:8001 \
    --timeout 120 \
    --access-logfile /var/log/detekta/gunicorn-access.log \
    --error-logfile /var/log/detekta/gunicorn-error.log
Restart=always
RestartSec=5
StandardOutput=append:/var/log/detekta/backend.log
StandardError=append:/var/log/detekta/backend-error.log

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now detekta-backend
sudo systemctl status detekta-backend
```

---

## Nginx Reverse Proxy

```bash
sudo nano /etc/nginx/sites-available/detekta-backend
```

```nginx
server {
    listen 80;
    server_name api.yourdomain.com;

    # Redirect HTTP → HTTPS (handled by Certbot later)
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    # SSL — filled in by Certbot
    ssl_certificate     /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    # Upload size limit (match MAX_FILE_SIZE_MB)
    client_max_body_size 210M;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), midi=(), sync-xhr=(), microphone=(), camera=(), magnetometer=(), gyroscope=(), fullscreen=(self), payment=()" always;

    # Proxy to Gunicorn
    location / {
        proxy_pass         http://127.0.0.1:8001;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_connect_timeout 10s;
    }

    # WebSocket — real-time audit logs
    location /api/ws/ {
        proxy_pass         http://127.0.0.1:8001;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
        proxy_read_timeout 3600s;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/detekta-backend /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## SSL — Let's Encrypt

```bash
sudo certbot --nginx -d api.yourdomain.com

# Auto-renewal test
sudo certbot renew --dry-run
```

Certbot automatically modifies the Nginx config with the certificate paths and sets up a cron/systemd timer for renewals.

---

## MobSF (Mobile Audits)

MobSF runs as an isolated Docker service. It is optional — non-mobile audits work without it.

```bash
cd /home/detekta/detekta/detekta-backend/mobsf
docker compose up -d
```

The compose file starts MobSF on port `8888` (or as configured). Verify:

```bash
curl http://localhost:8888/api/v1/version
```

To start MobSF automatically with the server:

```bash
sudo nano /etc/systemd/system/detekta-mobsf.service
```

```ini
[Unit]
Description=MobSF Docker Service
After=docker.service
Requires=docker.service

[Service]
User=detekta
WorkingDirectory=/home/detekta/detekta/detekta-backend/mobsf
ExecStart=/usr/bin/docker compose up
ExecStop=/usr/bin/docker compose down
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now detekta-mobsf
```

---

## Docker Compose (All-in-One)

If you prefer a fully containerised setup, create a `docker-compose.yml` at the project root:

```yaml
version: "3.9"

services:
  mongo:
    image: mongo:7
    restart: unless-stopped
    volumes:
      - mongo_data:/data/db
    environment:
      MONGO_INITDB_ROOT_USERNAME: detekta_user
      MONGO_INITDB_ROOT_PASSWORD: STRONG_PASSWORD_HERE

  backend:
    build: ./detekta-backend
    restart: unless-stopped
    depends_on:
      - mongo
    env_file:
      - ./detekta-backend/.env
    ports:
      - "127.0.0.1:8001:8001"
    volumes:
      - uploads:/var/detekta/uploads

  mobsf:
    image: opensecurity/mobile-security-framework-mobsf:latest
    restart: unless-stopped
    ports:
      - "127.0.0.1:8888:8000"
    volumes:
      - mobsf_data:/home/mobsf/.MobSF

volumes:
  mongo_data:
  uploads:
  mobsf_data:
```

Then add a `Dockerfile` inside `detekta-backend/`:

```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    nmap \
    libpango-1.0-0 libpangoft2-1.0-0 libffi-dev libcairo2 libpangocairo-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["gunicorn", "server:app", \
     "--workers", "4", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8001", \
     "--timeout", "120"]
```

Start everything:

```bash
docker compose up -d
```

---

## Health Check & Smoke Test

```bash
# Health endpoint
curl -s https://api.yourdomain.com/health | jq

# Swagger docs accessible
curl -sI https://api.yourdomain.com/docs | head -5

# Test user registration
curl -s -X POST https://api.yourdomain.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123!","name":"Test"}' | jq
```

Expected `200 OK` or `201 Created` on the registration endpoint.

---

## Updating the Application

```bash
sudo -u detekta -i
cd ~/detekta
git pull origin main

cd detekta-backend
source venv/bin/activate
pip install -r requirements.txt

sudo systemctl restart detekta-backend
sudo systemctl status detekta-backend
```

---

## Security Hardening

### Firewall (UFW)

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### Disable root SSH login

```bash
sudo nano /etc/ssh/sshd_config
# Set: PermitRootLogin no
# Set: PasswordAuthentication no (use SSH keys only)
sudo systemctl restart sshd
```

### Fail2ban (brute-force protection)

```bash
sudo apt install fail2ban -y
sudo systemctl enable --now fail2ban
```

### MongoDB — bind to localhost only

In `/etc/mongod.conf`:

```yaml
net:
  bindIp: 127.0.0.1
```

```bash
sudo systemctl restart mongod
```

### Rotate secrets periodically

- Regenerate `JWT_SECRET` every 90 days (invalidates all sessions — users must log in again).
- Rotate `ENCRYPTION_KEY` with a migration script that re-encrypts stored API keys.

---

## Monitoring & Logs

| Log file | Content |
|---|---|
| `/var/log/detekta/gunicorn-access.log` | All HTTP requests |
| `/var/log/detekta/gunicorn-error.log` | Gunicorn worker errors |
| `/var/log/detekta/backend.log` | Application stdout |
| `/var/log/detekta/backend-error.log` | Application stderr |

### Follow logs in real time

```bash
sudo journalctl -u detekta-backend -f
tail -f /var/log/detekta/gunicorn-error.log
```

### Log rotation

```bash
sudo nano /etc/logrotate.d/detekta
```

```
/var/log/detekta/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 detekta detekta
    postrotate
        systemctl reload detekta-backend > /dev/null 2>&1 || true
    endscript
}
```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `502 Bad Gateway` from Nginx | Gunicorn not running or wrong port | `sudo systemctl status detekta-backend` |
| `Connection refused` on port 8001 | Backend not started | Check `.env`, run `gunicorn` manually to see errors |
| `Motor connection error` | MongoDB not running or wrong `MONGO_URL` | `sudo systemctl status mongod` |
| PDF generation fails | Missing WeasyPrint system fonts / Pango | `sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libcairo2` |
| MobSF `Connection refused` | Docker container not running | `docker ps`, `docker compose up -d` in `mobsf/` |
| `nmap: command not found` | nmap not installed | `sudo apt install nmap` |
| JWT errors after key rotation | Old tokens using previous `JWT_SECRET` | Expected — users must log in again |
| CORS blocked by browser | `CORS_ORIGINS` missing frontend domain | Add the frontend URL to `CORS_ORIGINS` in `.env` and restart |
