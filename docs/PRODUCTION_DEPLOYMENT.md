# Silhouette Reaper // Production Deployment Guide

This guide provides end-to-end instructions for deploying the **Silhouette Reaper Anonymous Digital Forensics Platform** in a small-to-medium production environment (Single Linux VPS or Docker container with persistent volumes).

---

## Option 1: Docker Deployment (Recommended)

### 1. Prerequisites
* Docker Engine 24.0+ & Docker Compose v2.0+
* Domain pointing to your server's public IP address (e.g. `forensics.yourdomain.com`)

### 2. Deploy Container
```bash
# Clone or copy the repository to your server
git clone <repo_url> /opt/silhouette-reaper
cd /opt/silhouette-reaper

# Build and start the container in detached mode
docker compose up -d --build
```

### 3. Verify Container Status
```bash
docker ps
docker logs -f silhouette-reaper-app
```

---

## Option 2: Bare-Metal Linux VPS Deployment (Ubuntu 22.04 / 24.04 LTS)

### 1. Install Node.js 22 & System Packages
```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get update
sudo apt-get install -y nodejs nginx certbot python3-certbot-nginx
```

### 2. Set Up Application Directory
```bash
sudo mkdir -p /var/www/silhouette-reaper
sudo chown -R $USER:$USER /var/www/silhouette-reaper
cp -r . /var/www/silhouette-reaper
cd /var/www/silhouette-reaper

# Install dependencies and build production bundle
npm ci
npm run build
```

### 3. Configure Systemd Service
```bash
sudo cp deploy/silhouette-reaper.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable silhouette-reaper
sudo systemctl start silhouette-reaper
sudo systemctl status silhouette-reaper
```

---

## Option 3: Reverse Proxy & Automated SSL Setup

### A. Using Nginx + Certbot (Let's Encrypt)
1. Copy the Nginx template:
   ```bash
   sudo cp deploy/nginx.conf /etc/nginx/sites-available/silhouette-reaper
   ```
2. Replace `forensics.yourdomain.com` with your real domain.
3. Enable site and test configuration:
   ```bash
   sudo ln -s /etc/nginx/sites-available/silhouette-reaper /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```
4. Obtain free SSL certificate:
   ```bash
   sudo certbot --nginx -d forensics.yourdomain.com
   ```

### B. Using Caddy (Automated Zero-Config SSL)
1. Install Caddy and copy `deploy/Caddyfile`:
   ```bash
   sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
   sudo systemctl reload caddy
   ```

---

## Storage & Backup Strategy

All mutable state is isolated under the `storage/` directory:
* `storage/database/forensics.db` — SQLite database file.
* `storage/evidence_vault/` — Preserved bit-stream binaries (`0444`/`0400`).
* `storage/artifacts_store/` — Parsed forensic artifacts.
* `storage/reports_registry/` — Sealed PDF examination reports.

### Automated Nightly Backup Cron
```bash
# Add to crontab (crontab -e)
0 3 * * * tar -czf /backups/forensics_$(date +\%F).tar.gz /var/www/silhouette-reaper/storage/
```
