#!/bin/bash

echo "=== Testing upstream stream source directly ==="
curl -I "http://103.10.30.130:8081/viatv/viastarsports1hd/chunks.m3u8" 2>&1 | head -10

echo -e "\n=== Testing through nginx (should require auth) ==="
curl -I "http://localhost:3001/api/stream/viastarsports1hd/chunks.m3u8" 2>&1 | head -10

echo -e "\n=== Testing with auth token (replace YOUR_TOKEN) ==="
echo "curl -I 'http://localhost:3001/api/stream/viastarsports1hd/chunks.m3u8' -H 'Authorization: Bearer YOUR_TOKEN'"

echo -e "\n=== Check nginx error log for upstream errors ==="
sudo tail -20 /var/log/nginx/error.log | grep -i "upstream\|connect\|refused"

echo -e "\n=== Test if nginx can resolve/reach upstream ==="
ping -c 2 103.10.30.130

echo -e "\n=== Test upstream port ==="
timeout 3 bash -c "</dev/tcp/103.10.30.130/8081" && echo "Port 8081 is open" || echo "Port 8081 is closed/unreachable"
