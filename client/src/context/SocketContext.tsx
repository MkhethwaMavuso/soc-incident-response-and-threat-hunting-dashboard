import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { socket } from '../services/socket'
import { useAuth } from './AuthContext'

interface SocketContextValue {
  socket: typeof import('../services/socket').socket
  connected: boolean
}

const SocketContext = createContext<SocketContextValue | null>(null)

export function SocketProvider({ children }: { children: ReactNode }) {
  const { token } = useAuth()
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    if (!token) {
      socket.disconnect()
      setConnected(false)
      return
    }
    socket.auth = { token }
    socket.on('connect', () => setConnected(true))
    socket.on('disconnect', () => setConnected(false))
    socket.connect()
    return () => {
      socket.removeAllListeners('connect')
      socket.removeAllListeners('disconnect')
      socket.disconnect()
      setConnected(false)
    }
  }, [token])

  return <SocketContext.Provider value={{ socket, connected }}>{children}</SocketContext.Provider>
}

export function useSocket() {
  const context = useContext(SocketContext)
  if (!context) throw new Error('useSocket must be used within SocketProvider.')
  return context
}