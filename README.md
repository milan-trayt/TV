# WebTV

A high-performance streaming TV application with AWS Cognito authentication and real-time admin management.

## Features

- 🔐 Secure authentication via AWS Cognito (email + Google OAuth)
- 📺 Low-latency HLS streaming with optimized buffering
- 👥 Real-time user whitelist management
- 🎬 Dynamic channel management
- 🛡️ Role-based access control (Super Admin / Admin / User)
- ⚡ Aggressive caching for minimal latency (<1ms auth overhead)
- 🎨 Clean TV-style interface with keyboard navigation

## Quick Start

See [SETUP.md](SETUP.md) for detailed setup instructions.

### 1. Configure Super Admin

```bash
cd backend
cp .env.example .env
# Edit .env and set SUPER_ADMIN_EMAIL
```

### 2. Start Backend

```bash
cd backend
npm install
npm start
```

### 3. Start Frontend

```bash
cd frontend
npm install
npm run dev
```

## Documentation

- **[SETUP.md](SETUP.md)** - Complete setup guide
- **[SECURITY.md](SECURITY.md)** - Security model and best practices
- **[API_ADMIN.md](API_ADMIN.md)** - Admin API documentation

## Admin Management

### Super Admin
- Set via `SUPER_ADMIN_EMAIL` environment variable
- Full control over users, admins, and channels
- Cannot be removed or demoted

### Regular Admins
- Can manage users and channels
- Cannot promote/demote other admins
- Promoted by super admin only

### Access Admin Panel
- Login as admin
- Press **'A'** key to open admin panel
- Manage users, admins, and channels in real-time

## Keyboard Shortcuts

- **↑↓** - Navigate channels
- **M** - Mute/Unmute
- **F** - Fullscreen
- **R** - Reload channel
- **A** - Admin panel (admins only)
- **Esc** - Close sidebar/panels

## Performance Optimizations

- JWT token caching (1 hour)
- In-memory user/channel lists
- Direct stream piping (no buffering)
- Connection keep-alive
- HLS.js low-latency mode
- Reduced buffer sizes (15s)

## Security Features

- ✅ Privilege escalation prevention
- ✅ Super admin protection
- ✅ Self-removal prevention
- ✅ Token verification caching
- ✅ Secure cookie-based streaming
- ✅ Role-based access control

See [SECURITY.md](SECURITY.md) for complete security documentation.
