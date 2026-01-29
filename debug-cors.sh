#!/bin/bash

echo "=== Checking nginx status ==="
sudo systemctl status nginx | head -5

echo -e "\n=== Checking ports ==="
sudo ss -tlnp | grep -E ':(3001|3002)'

echo -e "\n=== Testing OPTIONS preflight (CORS) ==="
curl -X OPTIONS "http://localhost:3001/api/stream/viastarsports1hd/chunks.m3u8" \
  -H "Origin: https://tv.milan-pokhrel.com.np" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: authorization" \
  -v 2>&1 | grep -E "< HTTP|< Access-Control"

echo -e "\n=== Testing GET with token (should work with real token) ==="
echo "Replace YOUR_TOKEN with actual token from browser localStorage"
curl -I "http://localhost:3001/api/stream/viastarsports1hd/chunks.m3u8" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Origin: https://tv.milan-pokhrel.com.np" \
  2>&1 | grep -E "HTTP|Access-Control"

echo -e "\n=== Checking nginx error log (last 10 lines) ==="
sudo tail -10 /var/log/nginx/error.log

echo -e "\n=== Testing if Node.js auth endpoint works ==="
curl "http://localhost:3002/auth/verify-stream" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  2>&1 | head -3
