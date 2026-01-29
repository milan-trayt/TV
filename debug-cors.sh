#!/bin/bash

echo "=== Checking nginx status ==="
sudo systemctl status nginx | head -5

echo -e "\n=== Checking ports ==="
sudo netstat -tlnp | grep -E ':(3001|3002)'

echo -e "\n=== Testing stream request with CORS ==="
curl -I "http://localhost:3001/api/stream/viastarsports1hd/chunks.m3u8" \
  -H "Authorization: Bearer test-token" \
  -H "Origin: http://localhost:5173" \
  2>&1

echo -e "\n=== Checking nginx error log (last 10 lines) ==="
sudo tail -10 /var/log/nginx/error.log

echo -e "\n=== Checking nginx access log (last 5 lines) ==="
sudo tail -5 /var/log/nginx/access.log

echo -e "\n=== Testing auth endpoint ==="
curl -I "http://localhost:3002/auth/verify-stream" \
  -H "Authorization: Bearer test-token" \
  2>&1
