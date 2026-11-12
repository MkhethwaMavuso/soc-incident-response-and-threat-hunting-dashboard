import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { api } from '../services/api'
import type { Role } from '../types'

export interface AuthUser {
  id: string
  name: string
  email: string
  role: Role
}

interface AuthContextValue {
  token: string | null
  user: AuthUser | null
  login: (email: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState(() => localStorage.getItem('soc-token'))
  const [user, setUser] = useState<AuthUser | null>(null)

  useEffect(() => {
    if (!token) return
    api.get('/auth/me').then(({ data }) => setUser(data.data)).catch(() => {
      localStorage.removeItem('soc-token')
      setToken(null)
    })
  }, [token])

  async function login(email: string, password: string) {
    const { data } = await api.post('/auth/login', { email, password })
    localStorage.setItem('soc-token', data.data.token)
    setUser(data.data.user)
    setToken(data.data.token)
  }

  function logout() {
    localStorage.removeItem('soc-token')
    setToken(null)
    setUser(null)
  }

  return <AuthContext.Provider value={{ token, user, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used within AuthProvider.')
  return context
}