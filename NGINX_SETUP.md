# nginx Setup Guide

## Architecture Overview

**Before:**
```
ALB (SSL) → Node.js:3001 → Proxies all streams
```

**After:**
```
ALB (SSL) → nginx:3001 → Node.js:3002 (API only)
                       → Stream source (direct, with auth)
```

## Benefits
- nginx handles stream proxying (much faster than Node.js)
- Node.js only handles API/auth (what it's good at)
- Reduced latency and buffering
- Better performance under load

## Installation Steps

### 1. Install nginx
```bash
sudo apt update
sudo apt install nginx -y
```

### 2. Deploy nginx config
```bash
# Copy the config file
sudo cp nginx-tv.conf /etc/nginx/sites-available/tv

# Create symlink to enable it
sudo ln -s /etc/nginx/sites-available/tv /etc/nginx/sites-enabled/tv

# Remove default site (optional)
sudo rm /etc/nginx/sites-enabled/default

# Test config
sudo nginx -t
```

### 3. Update backend port
The backend `.env` has been updated to use port 3002. Restart your Node.js server:
```bash
# If using screen
screen -r tv
# Press Ctrl+C to stop
node server.js

# Or if using systemd/pm2, restart the service
```

### 4. Start nginx
```bash
sudo systemctl start nginx
sudo systemctl enable nginx  # Auto-start on boot
```

### 5. Verify
```bash
# Check nginx status
sudo systemctl status nginx

# Check if ports are listening
sudo netstat -tlnp | grep -E ':(3001|3002)'

# Test health endpoint
curl http://localhost:3001/health
```

## How It Works

1. **API requests** (`/api/*`) → nginx forwards to Node.js:3002
2. **Stream requests** (`/api/stream/*/chunks.m3u8` or `*.ts`) → nginx:
   - First calls `/auth/verify-stream` on Node.js to check auth
   - If auth passes, proxies directly to stream source
   - If auth fails, returns 401/403
3. **Auth verification** is fast (just token check, no stream data)
4. **Stream data** never touches Node.js, goes directly through nginx

## Troubleshooting

### nginx won't start
```bash
# Check logs
sudo journalctl -u nginx -n 50

# Check config syntax
sudo nginx -t
```

### Port 3001 already in use
```bash
# Find what's using it
sudo lsof -i :3001

# Kill the process if it's old Node.js
sudo kill <PID>
```

### Streams not working
```bash
# Check nginx error log
sudo tail -f /var/log/nginx/error.log

# Check if auth endpoint works
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:3002/auth/verify-stream
```

### Node.js can't bind to 3002
```bash
# Make sure old process is stopped
pkill -f "node server.js"

# Check if port is free
sudo lsof -i :3002
```

## ALB Configuration

Your ALB should point to port 3001 (nginx), not 3002. No changes needed if it's already pointing to 3001.

## Rollback

If you need to rollback:
```bash
# Stop nginx
sudo systemctl stop nginx
sudo systemctl disable nginx

# Change backend/.env PORT back to 3001
# Restart Node.js server
```
