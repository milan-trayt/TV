# Quick Start - nginx Migration

## What Changed
- Backend now runs on port **3002** (was 3001)
- nginx runs on port **3001** and handles stream proxying
- All stream proxy code removed from Node.js
- Auth verification endpoint: `/auth/verify-stream` (no `/api` prefix)

## Setup Commands

```bash
# 1. Install nginx
sudo apt install nginx -y

# 2. Deploy config
sudo cp nginx-tv.conf /etc/nginx/sites-available/tv
sudo ln -s /etc/nginx/sites-available/tv /etc/nginx/sites-enabled/tv
sudo nginx -t

# 3. Stop old Node.js (if running on 3001)
screen -r tv
# Press Ctrl+C

# 4. Start nginx
sudo systemctl start nginx
sudo systemctl enable nginx

# 5. Start Node.js on new port (3002)
node server.js
# Or in screen: screen -S tv -dm node server.js
```

## Verify It Works

```bash
# Check both services are running
sudo netstat -tlnp | grep -E ':(3001|3002)'

# Should see:
# - nginx on 3001
# - node on 3002

# Test health
curl http://localhost:3001/health
```

## Your ALB
- Should already point to port 3001 ✓
- No changes needed

## Files Modified
- `backend/.env` - PORT changed to 3002
- `backend/server.js` - Removed stream proxy code, cleaned up unused vars
- `nginx-tv.conf` - New nginx config (place in `/etc/nginx/sites-available/tv`)

## Expected Performance
- Near real-time streaming (~5-10 seconds behind live)
- Minimal buffering with nginx direct proxy
- Lower latency (no Node.js overhead on streams)
- Better stability under load
- May experience occasional rebuffering if network is unstable (trade-off for low latency)
