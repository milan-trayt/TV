import { useState, useEffect } from 'react'
import './AdminPanel.css'

const API_URL = import.meta.env.VITE_API_URL || ''

function AdminPanel({ getToken, onClose, isSuperAdmin }) {
  const [activeTab, setActiveTab] = useState('users')
  const [users, setUsers] = useState(null)
  const [channels, setChannels] = useState(null)
  const [newEmail, setNewEmail] = useState('')
  const [newChannel, setNewChannel] = useState({ category: '', id: '', name: '' })
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    loadUsers()
    loadChannels()
  }, [])

  const apiCall = async (endpoint, method = 'GET', body = null) => {
    try {
      const options = {
        method,
        headers: {
          'Authorization': `Bearer ${getToken()}`,
          'Content-Type': 'application/json'
        }
      }
      if (body) options.body = JSON.stringify(body)
      
      const res = await fetch(`${API_URL}${endpoint}`, options)
      const data = await res.json()
      
      if (!res.ok) throw new Error(data.error || 'Request failed')
      return data
    } catch (err) {
      setError(err.message)
      throw err
    }
  }

  const loadUsers = async () => {
    try {
      const data = await apiCall('/api/admin/users')
      setUsers(data)
    } catch {}
  }

  const loadChannels = async () => {
    try {
      const data = await apiCall('/api/admin/channels')
      setChannels(data.channels)
    } catch {}
  }

  const addUser = async () => {
    if (!newEmail) return
    try {
      await apiCall('/api/admin/users/add', 'POST', { email: newEmail })
      setMessage(`Added ${newEmail}`)
      setNewEmail('')
      loadUsers()
    } catch {}
  }

  const removeUser = async (email) => {
    try {
      await apiCall('/api/admin/users/remove', 'POST', { email })
      setMessage(`Removed ${email}`)
      loadUsers()
    } catch {}
  }

  const toggleWhitelist = async () => {
    try {
      const data = await apiCall('/api/admin/users/toggle-whitelist', 'POST')
      setMessage(`Whitelist ${data.enabled ? 'enabled' : 'disabled'}`)
      loadUsers()
    } catch {}
  }

  const addAdmin = async (email) => {
    if (!isSuperAdmin) {
      setError('Only super admin can manage admins')
      return
    }
    try {
      await apiCall('/api/admin/admins/add', 'POST', { email })
      setMessage(`${email} is now an admin`)
      loadUsers()
    } catch {}
  }

  const removeAdmin = async (email) => {
    if (!isSuperAdmin) {
      setError('Only super admin can manage admins')
      return
    }
    try {
      await apiCall('/api/admin/admins/remove', 'POST', { email })
      setMessage(`Removed admin: ${email}`)
      loadUsers()
    } catch {}
  }

  const addChannel = async () => {
    if (!newChannel.category || !newChannel.id || !newChannel.name) return
    try {
      await apiCall('/api/admin/channels/add', 'POST', newChannel)
      setMessage(`Added channel: ${newChannel.name}`)
      setNewChannel({ category: '', id: '', name: '' })
      loadChannels()
    } catch {}
  }

  const removeChannel = async (category, id) => {
    try {
      await apiCall('/api/admin/channels/remove', 'POST', { category, id })
      setMessage(`Removed channel`)
      loadChannels()
    } catch {}
  }

  return (
    <div className="admin-overlay">
      <div className="admin-panel">
        <div className="admin-header">
          <div>
            <h2>Admin Panel</h2>
            {isSuperAdmin && <span className="super-admin-badge">Super Admin</span>}
          </div>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        {message && <div className="admin-message success">{message}</div>}
        {error && <div className="admin-message error">{error}</div>}

        <div className="admin-tabs">
          <button 
            className={activeTab === 'users' ? 'active' : ''} 
            onClick={() => setActiveTab('users')}
          >
            Users
          </button>
          <button 
            className={activeTab === 'channels' ? 'active' : ''} 
            onClick={() => setActiveTab('channels')}
          >
            Channels
          </button>
        </div>

        {activeTab === 'users' && users && (
          <div className="admin-content">
            <div className="admin-section">
              <div className="section-header">
                <h3>Whitelist ({users.whitelist.users.length})</h3>
                <button onClick={toggleWhitelist}>
                  {users.whitelist.enabled ? 'Disable' : 'Enable'}
                </button>
              </div>
              
              <div className="add-form">
                <input
                  type="email"
                  placeholder="user@example.com"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && addUser()}
                />
                <button onClick={addUser}>Add User</button>
              </div>

              <div className="user-list">
                {users.whitelist.users.map(email => (
                  <div key={email} className="user-item">
                    <span>{email}</span>
                    <div>
                      {isSuperAdmin && !users.admins.includes(email) && (
                        <button onClick={() => addAdmin(email)}>Make Admin</button>
                      )}
                      <button onClick={() => removeUser(email)}>Remove</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {isSuperAdmin && (
              <div className="admin-section">
                <h3>Admins ({users.admins.length})</h3>
                <div className="user-list">
                  {users.admins.map(email => (
                    <div key={email} className="user-item">
                      <span>{email}</span>
                      <button onClick={() => removeAdmin(email)}>Remove Admin</button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'channels' && channels && (
          <div className="admin-content">
            <div className="admin-section">
              <h3>Add Channel</h3>
              <div className="add-form channel-form">
                <input
                  type="text"
                  placeholder="Category"
                  value={newChannel.category}
                  onChange={(e) => setNewChannel({...newChannel, category: e.target.value})}
                />
                <input
                  type="text"
                  placeholder="Channel ID"
                  value={newChannel.id}
                  onChange={(e) => setNewChannel({...newChannel, id: e.target.value})}
                />
                <input
                  type="text"
                  placeholder="Channel Name"
                  value={newChannel.name}
                  onChange={(e) => setNewChannel({...newChannel, name: e.target.value})}
                />
                <button onClick={addChannel}>Add</button>
              </div>
            </div>

            <div className="admin-section">
              <h3>Channels</h3>
              {Object.entries(channels).map(([category, chs]) => (
                <div key={category} className="channel-category">
                  <h4>{category} ({chs.length})</h4>
                  <div className="channel-list">
                    {chs.map(ch => (
                      <div key={ch.id} className="channel-item">
                        <div>
                          <strong>{ch.name}</strong>
                          <span className="channel-id">{ch.id}</span>
                        </div>
                        <button onClick={() => removeChannel(category, ch.id)}>Remove</button>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default AdminPanel
