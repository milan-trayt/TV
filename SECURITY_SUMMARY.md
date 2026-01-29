# Security Configuration Summary

## CORS Whitelist

### Allowed Origins (Production)
- `https://tv.milan-pokhrel.com.np` - Frontend
- `https://milan-pokhrel.com.np` - Backend/API domain
- `http://localhost:5173` - **Local development only** (remove before production deployment)

### Where Configured
1. **nginx** (`nginx-tv.conf`) - Uses `map` directive to validate origins
2. **Node.js** (`backend/server.js`) - Express CORS middleware

## Security Features

### nginx Layer
- ✅ Origin whitelist validation (rejects unauthorized origins with 403)
- ✅ Authorization required for all stream requests
- ✅ `auth_request` to Node.js before proxying streams
- ✅ CORS credentials enabled (required for Authorization header)
- ✅ No wildcard (`*`) CORS - only specific origins allowed
- ✅ Upstream CORS headers hidden to prevent conflicts

### Node.js Layer
- ✅ JWT token verification (AWS Cognito)
- ✅ User whitelist check
- ✅ Admin role verification
- ✅ Token caching (1 hour TTL, max 1000 tokens)
- ✅ CORS origin validation
- ✅ No CORS allowed for unauthorized origins

### Authentication Flow
1. User logs in via Cognito → receives JWT token
2. Frontend stores token in localStorage
3. HLS.js CustomLoader adds `Authorization: Bearer <token>` to all requests
4. nginx receives request → calls `/auth/verify-stream` on Node.js
5. Node.js verifies JWT + checks whitelist
6. If valid, nginx proxies to stream source
7. If invalid, returns 401/403 with CORS headers

## Production Deployment Checklist

Before deploying to production:

### 1. Remove localhost from CORS whitelist

**nginx-tv.conf:**
```nginx
map $http_origin $cors_origin {
    default "";
    "~^https://tv\.milan-pokhrel\.com\.np$" $http_origin;
    "~^https://milan-pokhrel\.com\.np$" $http_origin;
    # Remove this line:
    # "~^http://localhost:5173$" $http_origin;
}
```

**backend/server.js:**
```javascript
const ALLOWED_ORIGINS = [
  'https://tv.milan-pokhrel.com.np',
  'https://milan-pokhrel.com.np'
  // Remove: 'http://localhost:5173'
]
```

### 2. Verify environment variables
- `SUPER_ADMIN_EMAIL` - Set to your email
- `COGNITO_*` - All Cognito credentials configured
- `PORT=3002` - Backend on correct port
- `SERVE_FRONTEND=false` - CloudFront serves frontend

### 3. Test security
```bash
# Should be rejected (unauthorized origin)
curl -H "Origin: https://evil.com" \
  https://milan-pokhrel.com.np/api/stream/test/chunks.m3u8

# Should be rejected (no auth)
curl -H "Origin: https://tv.milan-pokhrel.com.np" \
  https://milan-pokhrel.com.np/api/stream/test/chunks.m3u8

# Should work (valid origin + auth)
curl -H "Origin: https://tv.milan-pokhrel.com.np" \
  -H "Authorization: Bearer VALID_TOKEN" \
  https://milan-pokhrel.com.np/api/stream/test/chunks.m3u8
```

## Security Best Practices Applied

- ✅ No wildcard CORS
- ✅ Origin validation at multiple layers
- ✅ Authentication required for all protected resources
- ✅ Token-based auth (not cookies for streams)
- ✅ JWT verification with public key
- ✅ User whitelist system
- ✅ Admin privilege separation
- ✅ Super admin cannot be removed
- ✅ No privilege escalation possible
- ✅ Credentials flag enabled for CORS
- ✅ No sensitive data in URLs (tokens in headers only)
- ✅ Stream source IP not exposed to clients

## Potential Improvements (Optional)

1. **Rate limiting** - Add nginx rate limiting for API endpoints
2. **IP whitelist** - Restrict admin panel to specific IPs
3. **Token rotation** - Implement refresh token rotation
4. **Audit logging** - Log all admin actions
5. **HTTPS only** - Enforce HTTPS in nginx (redirect HTTP to HTTPS)
6. **Security headers** - Add X-Frame-Options, CSP, etc.
