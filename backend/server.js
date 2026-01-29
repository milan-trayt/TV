import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import jwt from 'jsonwebtoken'
import jwksClient from 'jwks-rsa'
import { readFileSync, writeFileSync, existsSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { 
  CognitoIdentityProviderClient, 
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  ForgotPasswordCommand,
  ConfirmForgotPasswordCommand,
  ResendConfirmationCodeCommand
} from '@aws-sdk/client-cognito-identity-provider'
import crypto from 'crypto'
import dotenv from 'dotenv'

dotenv.config()

const __dirname = dirname(fileURLToPath(import.meta.url))
const USERS_FILE = join(__dirname, 'users.json')

const app = express()
const PORT = process.env.PORT || 3001
const IS_PROD = process.env.NODE_ENV === 'production'
const SERVE_FRONTEND = process.env.SERVE_FRONTEND === 'true'

// Configuration
const COGNITO_REGION = process.env.COGNITO_REGION || 'us-east-1'
const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID
const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID
const COGNITO_CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET
const COGNITO_DOMAIN = process.env.COGNITO_DOMAIN
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:5173/callback'
const STREAM_BASE_URL = process.env.STREAM_BASE_URL

// Cognito client
const cognitoClient = new CognitoIdentityProviderClient({ region: COGNITO_REGION })

// Generate secret hash for Cognito (required when client has a secret)
const getSecretHash = (username) => {
  if (!COGNITO_CLIENT_SECRET) return undefined
  return crypto
    .createHmac('sha256', COGNITO_CLIENT_SECRET)
    .update(username + COGNITO_CLIENT_ID)
    .digest('base64')
}

// ============ USER MANAGEMENT ============

const loadUsers = () => {
  try {
    if (existsSync(USERS_FILE)) {
      return JSON.parse(readFileSync(USERS_FILE, 'utf-8'))
    }
  } catch {}
  return { whitelist: { enabled: true, users: [] }, admins: [] }
}

const saveUsers = (data) => {
  writeFileSync(USERS_FILE, JSON.stringify(data, null, 2))
  // Invalidate cache on save
  usersCache = data
  usersCacheTime = Date.now()
}

// Cache users in memory
let usersCache = loadUsers()
let usersCacheTime = Date.now()

const getCachedUsers = () => usersCache

const isWhitelisted = (email) => {
  const users = getCachedUsers()
  if (!users.whitelist.enabled) return true
  return users.whitelist.users.includes(email?.toLowerCase())
}

const isAdmin = (email) => {
  const users = getCachedUsers()
  return users.admins.includes(email?.toLowerCase())
}

const isSuperAdmin = (email) => {
  const superAdmin = process.env.SUPER_ADMIN_EMAIL?.toLowerCase()
  return superAdmin && email?.toLowerCase() === superAdmin
}

// JWKS client for token verification
const client = COGNITO_USER_POOL_ID ? jwksClient({
  jwksUri: `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}/.well-known/jwks.json`,
  cache: true,
  cacheMaxAge: 86400000
}) : null

const getKey = (header, callback) => {
  if (!client) return callback(new Error('Cognito not configured'))
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err)
    callback(null, key.getPublicKey())
  })
}

// Verify Cognito JWT with aggressive caching
const tokenCache = new Map()
const TOKEN_CACHE_TTL = 3600000 // 1 hour - tokens are valid, cache aggressively

const verifyToken = (token) => {
  return new Promise((resolve, reject) => {
    if (!COGNITO_USER_POOL_ID) {
      return resolve({ sub: 'dev-user', email: 'dev@local' })
    }
    
    // Check cache first
    const cached = tokenCache.get(token)
    if (cached && Date.now() - cached.time < TOKEN_CACHE_TTL) {
      return resolve(cached.user)
    }
    
    jwt.verify(token, getKey, {
      issuer: `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}`,
      algorithms: ['RS256']
    }, (err, decoded) => {
      if (err) {
        tokenCache.delete(token)
        reject(err)
      } else {
        tokenCache.set(token, { user: decoded, time: Date.now() })
        // Limit cache size
        if (tokenCache.size > 1000) {
          const firstKey = tokenCache.keys().next().value
          tokenCache.delete(firstKey)
        }
        resolve(decoded)
      }
    })
  })
}

// Admin middleware
const adminMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' })
    }
    const token = authHeader.split(' ')[1]
    const user = await verifyToken(token)
    
    if (!isAdmin(user.email)) {
      return res.status(403).json({ error: 'Admin access required' })
    }
    
    req.user = user
    next()
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' })
  }
}

// Auth middleware - verifies token + checks whitelist
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' })
    }
    const token = authHeader.split(' ')[1]
    const user = await verifyToken(token)
    
    // Check whitelist
    if (!isWhitelisted(user.email)) {
      return res.status(403).json({ error: 'Access denied. Contact admin for access.' })
    }
    
    req.user = user
    next()
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' })
  }
}

// Stream auth middleware - checks cookie
const streamAuthMiddleware = async (req, res, next) => {
  try {
    const token = req.cookies?.stream_token
    if (!token) {
      return res.status(401).json({ error: 'No token' })
    }
    const user = await verifyToken(token)
    
    if (!isWhitelisted(user.email)) {
      return res.status(403).json({ error: 'Access denied' })
    }
    
    req.user = user
    next()
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' })
  }
}

// CORS - explicit origins
const ALLOWED_ORIGINS = [
  'https://tv.pokhrelmilan.com.np',
  'https://tvapi.pokhrelmilan.com.np'
]

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true)
    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true)
    }
    return callback(null, true)
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}))
app.use(cookieParser())
app.use(express.json())

// ============ CHANNEL MANAGEMENT ============

// In-memory channel cache - loaded once, updated via admin API
let channelsCache = {
  Sports: [
    { id: 'viastarsports1hd', name: 'Star Sports 1 HD' },
    { id: 'viastarsports2hd', name: 'Star Sports 2 HD' }
  ],
  Entertainment: [
    { id: 'viastargoldhd', name: 'Star Gold HD' },
    { id: 'viacolors', name: 'Colors' },
    { id: 'viasonyhd', name: 'Sony HD' },
    { id: 'viasonysabhd', name: 'Sony SAB HD' },
    { id: 'viasonypix', name: 'Sony PIX' },
    { id: 'viazeecinema', name: 'Zee Cinema' },
    { id: 'viazeeanmol', name: 'Zee Anmol' },
    { id: 'viazeecafehd', name: 'Zee Cafe HD' },
    { id: 'viastarmovies', name: 'Star Movies' }
  ],
  News: [
    { id: 'viaaajtak', name: 'Aaj Tak' },
    { id: 'viazeenews', name: 'Zee News' }
  ],
  Kids: [
    { id: 'viadiscoverykids', name: 'Discovery Kids' },
    { id: 'vianickjr', name: 'Nick Jr' },
    { id: 'viapogo', name: 'Pogo' },
    { id: 'vianick', name: 'Nick' }
  ],
  Infotainment: [
    { id: 'viadiscoveryhd', name: 'Discovery HD' },
    { id: 'vianatgeowildhd', name: 'Nat Geo Wild HD' },
    { id: 'viaanimalplanet', name: 'Animal Planet' },
    { id: 'viatlc', name: 'TLC' }
  ],
  Music: [
    { id: 'viamtv', name: 'MTV' },
    { id: 'viazing', name: 'Zing' },
    { id: 'via9xm', name: '9XM' },
    { id: 'via9xjalwa', name: '9X Jalwa' }
  ]
}

// ============ AUTH ENDPOINTS ============

// Get auth config (login URL, etc) - no secrets exposed
app.get('/api/auth/config', (req, res) => {
  if (!COGNITO_DOMAIN || !COGNITO_CLIENT_ID) {
    return res.json({ configured: false })
  }
  
  const loginUrl = `https://${COGNITO_DOMAIN}/login?` + new URLSearchParams({
    client_id: COGNITO_CLIENT_ID,
    response_type: 'code',
    scope: 'email openid profile',
    redirect_uri: REDIRECT_URI
  })
  
  const googleUrl = `https://${COGNITO_DOMAIN}/oauth2/authorize?` + new URLSearchParams({
    client_id: COGNITO_CLIENT_ID,
    response_type: 'code',
    scope: 'email openid profile',
    redirect_uri: REDIRECT_URI,
    identity_provider: 'Google',
    prompt: 'select_account'
  })

  res.json({
    configured: true,
    loginUrl,
    googleUrl,
    signupUrl: loginUrl.replace('/login?', '/signup?')
  })
})

// ============ EMAIL AUTH (NO REDIRECT TO COGNITO UI) ============

// Sign up with email
app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password } = req.body
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email and password required' })
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' })
  }

  try {
    await cognitoClient.send(new SignUpCommand({
      ClientId: COGNITO_CLIENT_ID,
      SecretHash: getSecretHash(username),
      Username: username,
      Password: password,
      UserAttributes: [
        { Name: 'email', Value: email },
        { Name: 'preferred_username', Value: username }
      ]
    }))
    res.json({ success: true, message: 'Check your email for verification code' })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

// Verify email with code
app.post('/api/auth/verify', async (req, res) => {
  const { username, code } = req.body
  if (!username || !code) {
    return res.status(400).json({ error: 'Username and code required' })
  }

  try {
    await cognitoClient.send(new ConfirmSignUpCommand({
      ClientId: COGNITO_CLIENT_ID,
      SecretHash: getSecretHash(username),
      Username: username,
      ConfirmationCode: code
    }))
    res.json({ success: true, message: 'Email verified! You can now login.' })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

// Resend verification code
app.post('/api/auth/resend-code', async (req, res) => {
  const { username } = req.body
  if (!username) return res.status(400).json({ error: 'Username required' })

  try {
    await cognitoClient.send(new ResendConfirmationCodeCommand({
      ClientId: COGNITO_CLIENT_ID,
      SecretHash: getSecretHash(username),
      Username: username
    }))
    res.json({ success: true, message: 'Verification code sent' })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

// Login with username/email and password
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body
  if (!username || !password) {
    return res.status(400).json({ error: 'Username/email and password required' })
  }

  try {
    const result = await cognitoClient.send(new InitiateAuthCommand({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: COGNITO_CLIENT_ID,
      AuthParameters: {
        USERNAME: username,
        PASSWORD: password,
        SECRET_HASH: getSecretHash(username)
      }
    }))

    const tokens = result.AuthenticationResult
    const decoded = jwt.decode(tokens.IdToken)

    res.json({
      access_token: tokens.AccessToken,
      id_token: tokens.IdToken,
      refresh_token: tokens.RefreshToken,
      user: {
        email: decoded.email,
        sub: decoded.sub,
        name: decoded.preferred_username || decoded.name || decoded.email
      }
    })
  } catch (err) {
    if (err.name === 'UserNotConfirmedException') {
      return res.status(400).json({ error: 'Please verify your email first', needsVerification: true })
    }
    res.status(401).json({ error: err.message })
  }
})

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body
  if (!email) return res.status(400).json({ error: 'Email required' })

  try {
    await cognitoClient.send(new ForgotPasswordCommand({
      ClientId: COGNITO_CLIENT_ID,
      SecretHash: getSecretHash(email),
      Username: email
    }))
    res.json({ success: true, message: 'Password reset code sent to your email' })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

// Reset password with code
app.post('/api/auth/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body
  if (!email || !code || !newPassword) {
    return res.status(400).json({ error: 'Email, code, and new password required' })
  }

  try {
    await cognitoClient.send(new ConfirmForgotPasswordCommand({
      ClientId: COGNITO_CLIENT_ID,
      SecretHash: getSecretHash(email),
      Username: email,
      ConfirmationCode: code,
      Password: newPassword
    }))
    res.json({ success: true, message: 'Password reset successful! You can now login.' })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

// Exchange auth code for tokens (Google OAuth callback)
app.post('/api/auth/token', async (req, res) => {
  const { code } = req.body
  
  if (!COGNITO_DOMAIN || !COGNITO_CLIENT_ID) {
    return res.json({
      access_token: 'dev-token',
      id_token: 'dev-token',
      user: { email: 'dev@local', sub: 'dev-user' }
    })
  }

  try {
    const tokenUrl = `https://${COGNITO_DOMAIN}/oauth2/token`
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: COGNITO_CLIENT_ID,
      code,
      redirect_uri: REDIRECT_URI
    })
    
    // Add client secret if configured
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' }
    if (COGNITO_CLIENT_SECRET) {
      const auth = Buffer.from(`${COGNITO_CLIENT_ID}:${COGNITO_CLIENT_SECRET}`).toString('base64')
      headers['Authorization'] = `Basic ${auth}`
    }

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers,
      body: params
    })

    if (!response.ok) {
      const error = await response.text()
      console.error('Token exchange failed:', error)
      return res.status(400).json({ error: 'Token exchange failed' })
    }

    const tokens = await response.json()
    
    // Decode ID token to get user info
    const decoded = jwt.decode(tokens.id_token)
    
    res.json({
      access_token: tokens.access_token,
      id_token: tokens.id_token,
      refresh_token: tokens.refresh_token,
      user: {
        email: decoded.email,
        sub: decoded.sub,
        name: decoded.name || decoded.email
      }
    })
  } catch (err) {
    console.error('Token error:', err)
    res.status(500).json({ error: 'Authentication failed' })
  }
})

// Refresh token
app.post('/api/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body
  
  if (!COGNITO_DOMAIN || !COGNITO_CLIENT_ID || !refresh_token) {
    return res.status(400).json({ error: 'Invalid request' })
  }

  try {
    const tokenUrl = `https://${COGNITO_DOMAIN}/oauth2/token`
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: COGNITO_CLIENT_ID,
      refresh_token
    })

    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' }
    if (COGNITO_CLIENT_SECRET) {
      const auth = Buffer.from(`${COGNITO_CLIENT_ID}:${COGNITO_CLIENT_SECRET}`).toString('base64')
      headers['Authorization'] = `Basic ${auth}`
    }

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers,
      body: params
    })

    if (!response.ok) {
      return res.status(401).json({ error: 'Refresh failed' })
    }

    const tokens = await response.json()
    const decoded = jwt.decode(tokens.id_token)

    res.json({
      access_token: tokens.access_token,
      id_token: tokens.id_token,
      user: {
        email: decoded.email,
        sub: decoded.sub,
        name: decoded.name || decoded.email
      }
    })
  } catch (err) {
    res.status(500).json({ error: 'Refresh failed' })
  }
})

// Verify current token
app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ user: req.user })
})

// Logout URL
app.get('/api/auth/logout-url', (req, res) => {
  if (!COGNITO_DOMAIN || !COGNITO_CLIENT_ID) {
    return res.json({ url: null })
  }
  
  const logoutUrl = `https://${COGNITO_DOMAIN}/logout?` + new URLSearchParams({
    client_id: COGNITO_CLIENT_ID,
    logout_uri: REDIRECT_URI.replace('/callback', '')
  })
  
  res.json({ url: logoutUrl })
})

// Get channels - all users use proxy
app.get('/api/channels', authMiddleware, (req, res) => {
  res.json({
    channels: channelsCache,
    user: { email: req.user.email },
    isAdmin: isAdmin(req.user.email),
    isSuperAdmin: isSuperAdmin(req.user.email)
  })
})

// ============ ADMIN ENDPOINTS ============

// Get all users (admin only)
app.get('/api/admin/users', adminMiddleware, (req, res) => {
  const users = getCachedUsers()
  res.json(users)
})

// Add user to whitelist (admin only)
app.post('/api/admin/users/add', adminMiddleware, (req, res) => {
  const { email } = req.body
  if (!email) return res.status(400).json({ error: 'Email required' })
  
  const users = getCachedUsers()
  const lowerEmail = email.toLowerCase()
  
  if (!users.whitelist.users.includes(lowerEmail)) {
    users.whitelist.users.push(lowerEmail)
    saveUsers(users)
  }
  
  res.json({ success: true, users: users.whitelist.users })
})

// Remove user from whitelist (admin only)
app.post('/api/admin/users/remove', adminMiddleware, (req, res) => {
  const { email } = req.body
  if (!email) return res.status(400).json({ error: 'Email required' })
  
  const users = getCachedUsers()
  const lowerEmail = email.toLowerCase()
  
  // Prevent removing yourself
  if (lowerEmail === req.user.email.toLowerCase()) {
    return res.status(400).json({ error: 'Cannot remove yourself' })
  }
  
  users.whitelist.users = users.whitelist.users.filter(e => e !== lowerEmail)
  saveUsers(users)
  
  res.json({ success: true, users: users.whitelist.users })
})

// Toggle whitelist enabled/disabled (admin only)
app.post('/api/admin/users/toggle-whitelist', adminMiddleware, (req, res) => {
  const users = getCachedUsers()
  users.whitelist.enabled = !users.whitelist.enabled
  saveUsers(users)
  
  res.json({ success: true, enabled: users.whitelist.enabled })
})

// Add admin (super admin only - requires SUPER_ADMIN_EMAIL env var)
app.post('/api/admin/admins/add', adminMiddleware, (req, res) => {
  const { email } = req.body
  if (!email) return res.status(400).json({ error: 'Email required' })
  
  // Only super admin can add admins
  const superAdmin = process.env.SUPER_ADMIN_EMAIL?.toLowerCase()
  if (!superAdmin || req.user.email.toLowerCase() !== superAdmin) {
    return res.status(403).json({ error: 'Only super admin can add admins' })
  }
  
  const users = getCachedUsers()
  const lowerEmail = email.toLowerCase()
  
  // Auto-add to whitelist if not already there
  if (!users.whitelist.users.includes(lowerEmail)) {
    users.whitelist.users.push(lowerEmail)
  }
  
  if (!users.admins.includes(lowerEmail)) {
    users.admins.push(lowerEmail)
    saveUsers(users)
  }
  
  res.json({ success: true, admins: users.admins })
})

// Remove admin (super admin only)
app.post('/api/admin/admins/remove', adminMiddleware, (req, res) => {
  const { email } = req.body
  if (!email) return res.status(400).json({ error: 'Email required' })
  
  // Only super admin can remove admins
  const superAdmin = process.env.SUPER_ADMIN_EMAIL?.toLowerCase()
  if (!superAdmin || req.user.email.toLowerCase() !== superAdmin) {
    return res.status(403).json({ error: 'Only super admin can remove admins' })
  }
  
  const users = getCachedUsers()
  const lowerEmail = email.toLowerCase()
  
  // Prevent removing super admin
  if (lowerEmail === superAdmin) {
    return res.status(400).json({ error: 'Cannot remove super admin' })
  }
  
  // Prevent removing yourself
  if (lowerEmail === req.user.email.toLowerCase()) {
    return res.status(400).json({ error: 'Cannot remove yourself' })
  }
  
  users.admins = users.admins.filter(e => e !== lowerEmail)
  saveUsers(users)
  
  res.json({ success: true, admins: users.admins })
})

// Get channels (admin only)
app.get('/api/admin/channels', adminMiddleware, (req, res) => {
  res.json({ channels: channelsCache })
})

// Update channels (admin only)
app.post('/api/admin/channels', adminMiddleware, (req, res) => {
  const { channels } = req.body
  if (!channels) return res.status(400).json({ error: 'Channels required' })
  
  // Validate structure
  if (typeof channels !== 'object') {
    return res.status(400).json({ error: 'Invalid channels format' })
  }
  
  channelsCache = channels
  res.json({ success: true, channels: channelsCache })
})

// Add channel to category (admin only)
app.post('/api/admin/channels/add', adminMiddleware, (req, res) => {
  const { category, id, name } = req.body
  if (!category || !id || !name) {
    return res.status(400).json({ error: 'Category, id, and name required' })
  }
  
  if (!channelsCache[category]) {
    channelsCache[category] = []
  }
  
  // Check if channel already exists
  const exists = channelsCache[category].some(ch => ch.id === id)
  if (!exists) {
    channelsCache[category].push({ id, name })
  }
  
  res.json({ success: true, channels: channelsCache })
})

// Remove channel (admin only)
app.post('/api/admin/channels/remove', adminMiddleware, (req, res) => {
  const { category, id } = req.body
  if (!category || !id) {
    return res.status(400).json({ error: 'Category and id required' })
  }
  
  if (channelsCache[category]) {
    channelsCache[category] = channelsCache[category].filter(ch => ch.id !== id)
    
    // Remove empty categories
    if (channelsCache[category].length === 0) {
      delete channelsCache[category]
    }
  }
  
  res.json({ success: true, channels: channelsCache })
})

// Rename category (admin only)
app.post('/api/admin/channels/rename-category', adminMiddleware, (req, res) => {
  const { oldName, newName } = req.body
  if (!oldName || !newName) {
    return res.status(400).json({ error: 'Old and new category names required' })
  }
  
  if (channelsCache[oldName]) {
    channelsCache[newName] = channelsCache[oldName]
    delete channelsCache[oldName]
  }
  
  res.json({ success: true, channels: channelsCache })
})

// Set stream cookie (called before streaming)
app.post('/api/stream/auth', authMiddleware, (req, res) => {
  const token = req.headers.authorization.split(' ')[1]
  
  res.cookie('stream_token', token, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: IS_PROD ? 'none' : 'lax',
    maxAge: 60 * 60 * 1000 // 1 hour
  })
  
  res.json({ success: true })
})

// ============ STREAM PROXY ============

// Proxy stream manifest
app.get('/api/stream/:channelId/chunks.m3u8', streamAuthMiddleware, async (req, res) => {
  const { channelId } = req.params
  const streamUrl = `${STREAM_BASE_URL}/${channelId}/chunks.m3u8`

  try {
    const response = await fetch(streamUrl, {
      headers: { 'Connection': 'keep-alive' }
    })
    if (!response.ok) return res.status(response.status).send('Stream unavailable')

    const manifest = await response.text()
    
    // Rewrite manifest URLs to go through proxy
    const rewritten = manifest
      .replace(/URI="([^"]+)"/g, (_, uri) => `URI="/api/stream/${channelId}/${uri}"`)
      .split('\n')
      .map(line => {
        if (line.startsWith('#') || line.trim() === '') return line
        return `/api/stream/${channelId}/${line.trim()}`
      })
      .join('\n')

    res.setHeader('Content-Type', 'application/vnd.apple.mpegurl')
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
    res.setHeader('Access-Control-Max-Age', '0')
    res.send(rewritten)
  } catch (err) {
    res.status(500).json({ error: 'Stream error' })
  }
})

// Proxy segments
app.get('/api/stream/:channelId/*', streamAuthMiddleware, async (req, res) => {
  const { channelId } = req.params
  const segment = req.params[0]
  const queryString = new URLSearchParams(req.query).toString()
  const segmentUrl = `${STREAM_BASE_URL}/${channelId}/${segment}${queryString ? '?' + queryString : ''}`

  try {
    const response = await fetch(segmentUrl, {
      headers: { 'Connection': 'keep-alive' }
    })
    if (!response.ok) return res.status(response.status).send('Segment unavailable')

    const contentType = response.headers.get('content-type') || 'video/mp2t'
    const contentLength = response.headers.get('content-length')

    // Set headers for low-latency streaming
    res.setHeader('Content-Type', contentType)
    if (contentLength) res.setHeader('Content-Length', contentLength)
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
    res.setHeader('Pragma', 'no-cache')
    res.setHeader('Expires', '0')
    res.setHeader('Accept-Ranges', 'bytes')
    res.setHeader('Connection', 'keep-alive')
    
    // Disable buffering
    res.setHeader('X-Accel-Buffering', 'no')

    // Pipe directly - much faster than manual chunking
    response.body.pipe(res)
  } catch (err) {
    if (!res.headersSent) {
      res.status(500).json({ error: 'Segment error' })
    }
  }
})

// Health check
app.get('/health', (req, res) => {
  const users = getCachedUsers()
  res.json({ 
    status: 'ok', 
    cognito: !!COGNITO_USER_POOL_ID,
    whitelistEnabled: users.whitelist.enabled,
    userCount: users.whitelist.users.length,
    adminCount: users.admins.length,
    channelCount: Object.values(channelsCache).reduce((sum, chs) => sum + chs.length, 0),
    categories: Object.keys(channelsCache).length
  })
})

// Serve frontend static files (for container deployment)
if (SERVE_FRONTEND) {
  const frontendPath = join(__dirname, 'public')
  app.use(express.static(frontendPath))
  app.get('*', (req, res) => {
    res.sendFile(join(frontendPath, 'index.html'))
  })
}

app.listen(PORT, () => {
  const users = getCachedUsers()
  const superAdmin = process.env.SUPER_ADMIN_EMAIL
  
  // Initialize super admin if set and not in admins list
  if (superAdmin) {
    const lowerSuperAdmin = superAdmin.toLowerCase()
    if (!users.admins.includes(lowerSuperAdmin)) {
      users.admins.push(lowerSuperAdmin)
      if (!users.whitelist.users.includes(lowerSuperAdmin)) {
        users.whitelist.users.push(lowerSuperAdmin)
      }
      saveUsers(users)
      console.log(`✓ Super admin initialized: ${superAdmin}`)
    }
  }
  
  console.log(`Server running on port ${PORT}`)
  console.log(`Cognito: ${COGNITO_USER_POOL_ID ? 'CONFIGURED' : 'DEV MODE'}`)
  console.log(`Super Admin: ${superAdmin || 'NOT SET - Set SUPER_ADMIN_EMAIL env var'}`)
  console.log(`Whitelist: ${users.whitelist.enabled ? 'ENABLED' : 'DISABLED'} (${users.whitelist.users.length} users)`)
  console.log(`Admins: ${users.admins.length}`)
  console.log(`Channels: ${Object.values(channelsCache).reduce((sum, chs) => sum + chs.length, 0)} across ${Object.keys(channelsCache).length} categories`)
  if (SERVE_FRONTEND) console.log(`Serving frontend from /public`)
})
