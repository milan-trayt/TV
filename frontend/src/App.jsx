import { useState, useRef, useEffect, useCallback } from 'react'
import Hls from 'hls.js'
import AdminPanel from './AdminPanel'
import './App.css'

const API_URL = import.meta.env.VITE_API_URL || ''

// Auth context
const useAuth = () => {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [authConfig, setAuthConfig] = useState(null)
  const [accessDenied, setAccessDenied] = useState(false)

  useEffect(() => {
    const init = async () => {
      // Check for stored token
      const token = localStorage.getItem('id_token')
      const storedUser = localStorage.getItem('user')
      if (token && storedUser) {
        setUser(JSON.parse(storedUser))
        verifyToken(token)
      } else {
        fetchAuthConfig()
      }
      setLoading(false)

      // Handle OAuth callback
      const params = new URLSearchParams(window.location.search)
      const code = params.get('code')
      if (code) {
        exchangeCode(code)
        window.history.replaceState({}, '', window.location.pathname)
      }
    }

    init()
  }, [])

  const fetchAuthConfig = async () => {
    try {
      const res = await fetch(`${API_URL}/api/auth/config`)
      const config = await res.json()
      setAuthConfig(config)
    } catch (err) {
      console.error('Failed to fetch auth config')
    }
  }

  const verifyToken = async (token) => {
    try {
      const res = await fetch(`${API_URL}/api/auth/me`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (!res.ok) {
        logout()
      }
    } catch {
      logout()
    }
  }

  const exchangeCode = async (code) => {
    try {
      const res = await fetch(`${API_URL}/api/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      })
      if (res.ok) {
        const data = await res.json()
        localStorage.setItem('id_token', data.id_token)
        localStorage.setItem('access_token', data.access_token)
        if (data.refresh_token) localStorage.setItem('refresh_token', data.refresh_token)
        localStorage.setItem('user', JSON.stringify(data.user))
        setUser(data.user)
      }
    } catch (err) {
      console.error('Auth failed:', err)
    }
  }

  const logout = async () => {
    localStorage.removeItem('id_token')
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    localStorage.removeItem('user')
    setUser(null)
    setAccessDenied(false)
    
    // Just reload the page - Cognito logout URL often has issues
    window.location.href = '/'
  }

  const getToken = () => localStorage.getItem('id_token')
  
  const setDenied = (denied) => setAccessDenied(denied)

  return { user, loading, authConfig, logout, getToken, fetchAuthConfig, accessDenied, setDenied }
}

function LoginPage({ authConfig, onRefresh }) {
  useEffect(() => {
    onRefresh()
  }, [])

  const configured = authConfig?.configured
  const [view, setView] = useState('login') // login, signup, verify, forgot, reset
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  const validateEmail = (email) => {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  }

  const handleEmailLogin = async (e) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)
    try {
      const res = await fetch(`${API_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: email, password }) // email field used as username/email
      })
      const data = await res.json()
      if (!res.ok) {
        if (data.needsVerification) {
          setUsername(email) // store for verification
          setView('verify')
          setMessage('Please verify your email first')
        } else {
          setError(data.error)
        }
        return
      }
      localStorage.setItem('id_token', data.id_token)
      localStorage.setItem('access_token', data.access_token)
      if (data.refresh_token) localStorage.setItem('refresh_token', data.refresh_token)
      localStorage.setItem('user', JSON.stringify(data.user))
      window.location.reload()
    } catch {
      setError('Connection failed')
    } finally {
      setIsLoading(false)
    }
  }

  const handleSignup = async (e) => {
    e.preventDefault()
    setError('')
    
    if (!validateEmail(email)) {
      setError('Please enter a valid email address')
      return
    }
    if (username.length < 3) {
      setError('Username must be at least 3 characters')
      return
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }
    
    setIsLoading(true)
    try {
      const res = await fetch(`${API_URL}/api/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password })
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error)
        return
      }
      setMessage(data.message)
      setView('verify')
    } catch {
      setError('Connection failed')
    } finally {
      setIsLoading(false)
    }
  }

  const handleVerify = async (e) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)
    try {
      const res = await fetch(`${API_URL}/api/auth/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, code })
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error)
        return
      }
      setMessage(data.message)
      setView('login')
      setCode('')
    } catch {
      setError('Connection failed')
    } finally {
      setIsLoading(false)
    }
  }

  const handleForgotPassword = async (e) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)
    try {
      const res = await fetch(`${API_URL}/api/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error)
        return
      }
      setMessage(data.message)
      setView('reset')
    } catch {
      setError('Connection failed')
    } finally {
      setIsLoading(false)
    }
  }

  const handleResetPassword = async (e) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)
    try {
      const res = await fetch(`${API_URL}/api/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code, newPassword: password })
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error)
        return
      }
      setMessage(data.message)
      setView('login')
      setCode('')
      setPassword('')
    } catch {
      setError('Connection failed')
    } finally {
      setIsLoading(false)
    }
  }

  const handleResendCode = async () => {
    setError('')
    try {
      const res = await fetch(`${API_URL}/api/auth/resend-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      })
      const data = await res.json()
      if (res.ok) setMessage(data.message)
      else setError(data.error)
    } catch {
      setError('Connection failed')
    }
  }

  return (
    <div className="login-container">
      <div className="login-box">
        <div className="login-header">
          <h1>WebTV</h1>
          <p>Stream your favorite channels</p>
        </div>

        {message && <div className="auth-message success">{message}</div>}
        {error && <div className="auth-message error">{error}</div>}

        {view === 'login' && (
          <>
            {configured && (
              <a href={authConfig.googleUrl} className="btn btn-google">
                <svg viewBox="0 0 24 24" width="20" height="20">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                Continue with Google
              </a>
            )}
            <div className="divider"><span>or</span></div>
            <form onSubmit={handleEmailLogin} className="auth-form">
              <input
                type="text"
                placeholder="Username or Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <button type="submit" className="btn btn-email" disabled={isLoading}>
                {isLoading ? 'Signing in...' : 'Sign In'}
              </button>
            </form>
            <div className="auth-links">
              <button onClick={() => { setView('signup'); setError(''); setMessage(''); }}>Create account</button>
              <button onClick={() => { setView('forgot'); setError(''); setMessage(''); }}>Forgot password?</button>
            </div>
          </>
        )}

        {view === 'signup' && (
          <>
            <h2 className="auth-title">Create Account</h2>
            <form onSubmit={handleSignup} className="auth-form">
              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
              <input
                type="password"
                placeholder="Password (min 8 chars)"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <button type="submit" className="btn btn-email" disabled={isLoading}>
                {isLoading ? 'Creating...' : 'Create Account'}
              </button>
            </form>
            <div className="auth-links">
              <button onClick={() => { setView('login'); setError(''); setMessage(''); setUsername(''); }}>Back to login</button>
            </div>
          </>
        )}

        {view === 'verify' && (
          <>
            <h2 className="auth-title">Verify Email</h2>
            <p className="auth-subtitle">Enter the code sent to your email for {username}</p>
            <form onSubmit={handleVerify} className="auth-form">
              <input
                type="text"
                placeholder="Verification code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                required
              />
              <button type="submit" className="btn btn-email" disabled={isLoading}>
                {isLoading ? 'Verifying...' : 'Verify'}
              </button>
            </form>
            <div className="auth-links">
              <button onClick={handleResendCode}>Resend code</button>
              <button onClick={() => { setView('login'); setError(''); setMessage(''); }}>Back to login</button>
            </div>
          </>
        )}

        {view === 'forgot' && (
          <>
            <h2 className="auth-title">Reset Password</h2>
            <form onSubmit={handleForgotPassword} className="auth-form">
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
              <button type="submit" className="btn btn-email" disabled={isLoading}>
                {isLoading ? 'Sending...' : 'Send Reset Code'}
              </button>
            </form>
            <div className="auth-links">
              <button onClick={() => { setView('login'); setError(''); setMessage(''); }}>Back to login</button>
            </div>
          </>
        )}

        {view === 'reset' && (
          <>
            <h2 className="auth-title">Set New Password</h2>
            <form onSubmit={handleResetPassword} className="auth-form">
              <input
                type="text"
                placeholder="Reset code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                required
              />
              <input
                type="password"
                placeholder="New password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <button type="submit" className="btn btn-email" disabled={isLoading}>
                {isLoading ? 'Resetting...' : 'Reset Password'}
              </button>
            </form>
            <div className="auth-links">
              <button onClick={() => { setView('login'); setError(''); setMessage(''); }}>Back to login</button>
            </div>
          </>
        )}

        <div className="login-footer">
          <p>Secure authentication powered by AWS</p>
        </div>
      </div>
    </div>
  )
}


function TVPlayer({ user, logout, getToken, onAccessDenied }) {
  const [channels, setChannels] = useState({})
  const [channelList, setChannelList] = useState([])
  const [currentChannel, setCurrentChannel] = useState(null)
  const [currentIndex, setCurrentIndex] = useState(0)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [showSidebar, setShowSidebar] = useState(false)
  const [isMuted, setIsMuted] = useState(false)
  const [userInfo, setUserInfo] = useState(null)
  const [isAdmin, setIsAdmin] = useState(false)
  const [isSuperAdmin, setIsSuperAdmin] = useState(false)
  const [showAdminPanel, setShowAdminPanel] = useState(false)
  const [numberInput, setNumberInput] = useState('')
  const [numberTimeout, setNumberTimeout] = useState(null)
  const videoRef = useRef(null)
  const hlsRef = useRef(null)
  const sidebarTimeoutRef = useRef(null)
  const selectedChannelRef = useRef(null)

  // Fetch channels from backend
  useEffect(() => {
    const fetchChannels = async () => {
      try {
        const token = getToken()
        const res = await fetch(`${API_URL}/api/channels`, {
          headers: { Authorization: `Bearer ${token}` }
        })
        
        if (res.status === 403) {
          onAccessDenied()
          return
        }
        
        if (res.ok) {
          const data = await res.json()
          setChannels(data.channels)
          setUserInfo(data.user)
          setIsAdmin(data.isAdmin)
          setIsSuperAdmin(data.isSuperAdmin)
          
          // Set stream auth cookie
          await fetch(`${API_URL}/api/stream/auth`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}` },
            credentials: 'include'
          })
        }
      } catch (err) {
        console.error('Failed to fetch channels')
      }
    }
    fetchChannels()
  }, [getToken, onAccessDenied])

  // Flatten channels into list
  useEffect(() => {
    const list = Object.entries(channels).flatMap(([category, chs]) =>
      chs.map(ch => ({ ...ch, category }))
    )
    setChannelList(list)
    if (list.length > 0 && !currentChannel) {
      playChannel(list[0].id, list[0].name, 0)
      setSelectedIndex(0)
    }
  }, [channels])

  const getStreamUrl = useCallback((channelId) => {
    return `${API_URL}/api/stream/${channelId}/chunks.m3u8`
  }, [])

  const playChannel = useCallback((id, name, index) => {
    const url = getStreamUrl(id)
    setError(null)
    setLoading(true)
    setCurrentIndex(index)
    setCurrentChannel({ id, name, url })
  }, [getStreamUrl])

  const toggleMute = useCallback(() => {
    if (videoRef.current) {
      videoRef.current.muted = !videoRef.current.muted
      setIsMuted(videoRef.current.muted)
    }
  }, [])

  const toggleFullscreen = useCallback(() => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen()
    } else {
      document.exitFullscreen()
    }
  }, [])

  // HLS player effect
  useEffect(() => {
    if (!currentChannel || !videoRef.current) return

    const video = videoRef.current
    
    const handlePlaying = () => { 
      setLoading(false)
      setError(null)
    }

    const handleWaiting = () => {
      setLoading(true)
    }

    const handleError = () => {
      setError('Stream unavailable')
      setLoading(false)
    }

    video.addEventListener('playing', handlePlaying)
    video.addEventListener('waiting', handleWaiting)
    video.addEventListener('error', handleError)

    // Try native HLS first (Safari, iOS, some smart TVs)
    if (video.canPlayType('application/vnd.apple.mpegurl')) {
      // Native HLS - no CORS issues
      if (hlsRef.current) {
        hlsRef.current.destroy()
        hlsRef.current = null
      }
      video.src = currentChannel.url
      video.play().catch(() => {})
    } else if (Hls.isSupported()) {
      // HLS.js for Chrome/Firefox - requires CORS extension
      if (hlsRef.current) {
        hlsRef.current.destroy()
        hlsRef.current = null
      }

      const token = getToken() // Get token before creating HLS instance
      const hls = new Hls({
        enableWorker: true,
        lowLatencyMode: false,
        backBufferLength: 10,
        maxBufferLength: 30,
        maxMaxBufferLength: 60,
        maxBufferSize: 60 * 1000 * 1000,
        maxBufferHole: 0.5,
        highBufferWatchdogPeriod: 2,
        nudgeOffset: 0.1,
        nudgeMaxRetry: 3,
        maxFragLookUpTolerance: 0.25,
        liveSyncDurationCount: 3,
        liveMaxLatencyDurationCount: 10,
        liveDurationInfinity: false,
        manifestLoadingTimeOut: 10000,
        manifestLoadingMaxRetry: 2,
        manifestLoadingRetryDelay: 1000,
        levelLoadingTimeOut: 10000,
        levelLoadingMaxRetry: 2,
        fragLoadingTimeOut: 20000,
        fragLoadingMaxRetry: 2,
        startLevel: -1,
        abrEwmaDefaultEstimate: 500000,
        startFragPrefetch: true,
        testBandwidth: false,
        progressive: true,
        debug: false,
        xhrSetup: function(xhr, url) {
          // Add Authorization header to all HLS requests
          if (token) {
            xhr.setRequestHeader('Authorization', `Bearer ${token}`)
          }
        }
      })
      hlsRef.current = hls
      
      hls.on(Hls.Events.MANIFEST_PARSED, () => {
        setLoading(false)
        // Start playback immediately
        video.play().catch(() => {})
      })
      
      // Start playback as soon as first fragment is loaded
      hls.on(Hls.Events.FRAG_LOADED, (event, data) => {
        if (data.frag.sn === 0 || data.frag.sn === 1) {
          video.play().catch(() => {})
        }
      })
      
      hls.on(Hls.Events.ERROR, (_, data) => {
        if (data.fatal) {
          switch (data.type) {
            case Hls.ErrorTypes.NETWORK_ERROR:
              hls.startLoad()
              break
            case Hls.ErrorTypes.MEDIA_ERROR:
              hls.recoverMediaError()
              break
            default:
              setError('Stream unavailable - enable CORS extension')
              setLoading(false)
              break
          }
        }
      })

      hls.attachMedia(video)
      hls.loadSource(currentChannel.url)
    }

    return () => {
      video.removeEventListener('playing', handlePlaying)
      video.removeEventListener('waiting', handleWaiting)
      video.removeEventListener('error', handleError)
    }
  }, [currentChannel])

  // Cleanup HLS on unmount
  useEffect(() => {
    return () => {
      if (hlsRef.current) {
        hlsRef.current.destroy()
        hlsRef.current = null
      }
    }
  }, [])

  // Auto-scroll sidebar to selected channel
  useEffect(() => {
    if (showSidebar && selectedChannelRef.current) {
      selectedChannelRef.current.scrollIntoView({
        behavior: 'smooth',
        block: 'nearest'
      })
    }
  }, [selectedIndex, showSidebar])
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Don't handle keys if admin panel is open
      if (showAdminPanel) return
      
      if (channelList.length === 0) return

      // Number input for direct channel selection
      if (e.key >= '0' && e.key <= '9') {
        e.preventDefault()
        const newInput = numberInput + e.key
        setNumberInput(newInput)
        
        // Clear existing timeout
        if (numberTimeout) clearTimeout(numberTimeout)
        
        // Set new timeout to switch channel after 2 seconds
        const timeout = setTimeout(() => {
          const channelNum = parseInt(newInput)
          if (channelNum > 0 && channelNum <= channelList.length) {
            const idx = channelNum - 1
            const ch = channelList[idx]
            playChannel(ch.id, ch.name, idx)
            setSelectedIndex(idx)
          }
          setNumberInput('')
        }, 2000)
        
        setNumberTimeout(timeout)
        return
      }

      if (e.key === 'ArrowUp') {
        e.preventDefault()
        setShowSidebar(true)
        const newIndex = selectedIndex > 0 ? selectedIndex - 1 : channelList.length - 1
        setSelectedIndex(newIndex)
        
        // Auto-hide sidebar after 3 seconds of inactivity
        if (sidebarTimeoutRef.current) clearTimeout(sidebarTimeoutRef.current)
        sidebarTimeoutRef.current = setTimeout(() => setShowSidebar(false), 3000)
      } else if (e.key === 'ArrowDown') {
        e.preventDefault()
        setShowSidebar(true)
        const newIndex = selectedIndex < channelList.length - 1 ? selectedIndex + 1 : 0
        setSelectedIndex(newIndex)
        
        if (sidebarTimeoutRef.current) clearTimeout(sidebarTimeoutRef.current)
        sidebarTimeoutRef.current = setTimeout(() => setShowSidebar(false), 3000)
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault()
        const newIndex = currentIndex > 0 ? currentIndex - 1 : channelList.length - 1
        const ch = channelList[newIndex]
        playChannel(ch.id, ch.name, newIndex)
        setSelectedIndex(newIndex)
      } else if (e.key === 'ArrowRight') {
        e.preventDefault()
        const newIndex = currentIndex < channelList.length - 1 ? currentIndex + 1 : 0
        const ch = channelList[newIndex]
        playChannel(ch.id, ch.name, newIndex)
        setSelectedIndex(newIndex)
      } else if (e.key === 'Enter') {
        e.preventDefault()
        if (showSidebar && selectedIndex !== currentIndex) {
          const ch = channelList[selectedIndex]
          playChannel(ch.id, ch.name, selectedIndex)
        }
        setShowSidebar(false)
      } else if (e.key === 'm' || e.key === 'M') {
        e.preventDefault()
        toggleMute()
      } else if (e.key === 'f' || e.key === 'F') {
        e.preventDefault()
        toggleFullscreen()
      } else if (e.key === 'Escape') {
        setShowSidebar(false)
        setShowAdminPanel(false)
      } else if (e.key === 'r' || e.key === 'R') {
        e.preventDefault()
        if (currentChannel) playChannel(currentChannel.id, currentChannel.name, currentIndex)
      } else if ((e.key === 'a' || e.key === 'A') && isAdmin && !showAdminPanel) {
        e.preventDefault()
        setShowAdminPanel(true)
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [channelList, currentIndex, selectedIndex, currentChannel, playChannel, toggleMute, toggleFullscreen, isAdmin, showAdminPanel, numberInput, numberTimeout, showSidebar])

  const handleMouseMove = (e) => {
    if (e.clientX < 100) {
      setShowSidebar(true)
      if (sidebarTimeoutRef.current) clearTimeout(sidebarTimeoutRef.current)
    }
  }

  const handleSidebarLeave = () => {
    sidebarTimeoutRef.current = setTimeout(() => setShowSidebar(false), 500)
  }

  const handleSidebarEnter = () => {
    if (sidebarTimeoutRef.current) clearTimeout(sidebarTimeoutRef.current)
  }

  const handleLogout = () => {
    if (hlsRef.current) {
      hlsRef.current.destroy()
      hlsRef.current = null
    }
    logout()
  }

  return (
    <div className="tv-container" onMouseMove={handleMouseMove}>
      <video ref={videoRef} className="tv-video" autoPlay />

      {!currentChannel && (
        <div className="tv-placeholder">
          <div>Loading channels...</div>
        </div>
      )}

      {currentChannel && (
        <div className={`channel-info ${loading ? 'loading' : ''}`}>
          <div className="channel-number">
            {numberInput || currentIndex + 1}
          </div>
          <div className="channel-name">{currentChannel.name}</div>
          {loading && <div className="channel-status">Buffering...</div>}
          {error && <div className="channel-status error">{error}</div>}
          {numberInput && <div className="channel-status">Enter channel number...</div>}
        </div>
      )}

      <div
        className={`tv-sidebar ${showSidebar ? 'visible' : ''}`}
        onMouseEnter={handleSidebarEnter}
        onMouseLeave={handleSidebarLeave}
      >
        <div className="sidebar-header">
          <span>Channels</span>
          <span className="channel-count">{channelList.length}</span>
        </div>
        <div className="channel-list">
          {Object.entries(channels).map(([category, chs]) => (
            <div key={category} className="category-group">
              <div className="category-label">{category}</div>
              {chs.map((ch) => {
                const idx = channelList.findIndex(c => c.id === ch.id)
                return (
                  <div
                    key={ch.id}
                    ref={selectedIndex === idx ? selectedChannelRef : null}
                    className={`channel-item ${currentChannel?.id === ch.id ? 'active' : ''} ${selectedIndex === idx ? 'selected' : ''}`}
                    onClick={() => {
                      playChannel(ch.id, ch.name, idx)
                      setSelectedIndex(idx)
                      setShowSidebar(false)
                    }}
                  >
                    <span className="item-number">{idx + 1}</span>
                    <span className="item-name">{ch.name}</span>
                  </div>
                )
              })}
            </div>
          ))}
        </div>
        <div className="sidebar-footer">
          <div className="user-info">
            <div className="user-details">
              <span>{userInfo?.email || user?.email}</span>
            </div>
            <div className="user-actions">
              {isAdmin && (
                <button className="admin-btn" onClick={() => setShowAdminPanel(true)}>
                  Admin
                </button>
              )}
              <button className="logout-btn" onClick={handleLogout}>Logout</button>
            </div>
          </div>
          <div className="controls">
            <button onClick={toggleMute}>{isMuted ? '🔇' : '🔊'}</button>
            <button onClick={toggleFullscreen}>⛶</button>
          </div>
          <div className="shortcuts">
            ←→ Change • ↑↓ Navigate • Enter Select • 0-9 Go to • M Mute • F Fullscreen • R Reload
            {isAdmin && ' • A Admin'}
          </div>
        </div>
      </div>

      {showAdminPanel && (
        <AdminPanel 
          getToken={getToken}
          isSuperAdmin={isSuperAdmin}
          onClose={() => {
            setShowAdminPanel(false)
            // Reload channels after admin changes
            window.location.reload()
          }} 
        />
      )}
    </div>
  )
}

function AccessDeniedPage({ email, onLogout }) {
  return (
    <div className="login-container">
      <div className="login-box">
        <div className="login-header">
          <h1>Access Denied</h1>
          <p>Your account is not whitelisted</p>
        </div>
        <div className="access-denied-info">
          <p>Logged in as: <strong>{email}</strong></p>
          <p>Contact an administrator to request access.</p>
        </div>
        <button className="btn btn-email" onClick={onLogout}>
          Logout
        </button>
      </div>
    </div>
  )
}

function App() {
  const { user, loading, authConfig, logout, getToken, fetchAuthConfig, accessDenied, setDenied } = useAuth()

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="spinner"></div>
      </div>
    )
  }

  if (!user) {
    return <LoginPage authConfig={authConfig} onRefresh={fetchAuthConfig} />
  }

  if (accessDenied) {
    return <AccessDeniedPage email={user.email} onLogout={logout} />
  }

  return <TVPlayer user={user} logout={logout} getToken={getToken} onAccessDenied={() => setDenied(true)} />
}

export default App
