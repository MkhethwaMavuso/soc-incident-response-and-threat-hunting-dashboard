import type { Server } from 'socket.io'
import jwt from 'jsonwebtoken'
import { ThreatIndicator } from '../models/ThreatIndicator.model'
import { NETWORK_ZONES } from '../models/LogEntry.model'
import { User } from '../models/User.model'
import { requiredSecret } from '../middleware/auth'
import type { AccessTokenClaims, Role } from '../types/security'

export function registerSocketHandlers(io: Server) {
  io.use(async (socket, next) => {
    const token = socket.handshake.auth.token
    if (typeof token !== 'string') return next(new Error('Authentication required.'))
    try {
      const claims = jwt.verify(token, requiredSecret()) as jwt.JwtPayload & AccessTokenClaims
      const user = await User.findById(claims.sub).select('email role status')
      if (!user || user.status !== 'ACTIVE') return next(new Error('User account is no longer active.'))
      socket.data.user = { sub: user.id, role: user.role, email: user.email }
      next()
    } catch (error) {
      if (error instanceof Error && (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError')) {
        next(new Error('Invalid or expired access token.'))
        return
      }
      next(error instanceof Error ? error : new Error('Socket authentication failed.'))
    }
  })

  io.on('connection', (socket) => {
    socket.join(`role:${socket.data.user.role as Role}`)
    socket.emit('connection:ready', { connectedAt: new Date().toISOString() })
  })

  let nextEmission: NodeJS.Timeout
  const emitTelemetry = async () => {
    const sourceIp = `10.24.${Math.floor(Math.random() * 20)}.${Math.floor(Math.random() * 240 + 10)}`
    const targetNodes = [
      { hostname: 'FIN-WS-042', ipAddress: '10.24.8.42', nodeType: 'WORKSTATION', os: 'Windows 11' },
      { hostname: 'PROD-DB-03', ipAddress: '10.32.4.23', nodeType: 'DATABASE_SERVER', os: 'Ubuntu 24.04' },
      { hostname: 'EXT-GW-01', ipAddress: '203.0.113.18', nodeType: 'WEB_GATEWAY', os: 'Linux' },
      { hostname: 'IDP-CORE-01', ipAddress: '10.24.0.12', nodeType: 'DOMAIN_CONTROLLER', os: 'Windows Server 2022' },
    ] as const
    const targetNode = targetNodes[Math.floor(Math.random() * targetNodes.length)]
    const destIp = targetNode.ipAddress
    const networkZone = NETWORK_ZONES[Math.floor(Math.random() * NETWORK_ZONES.length)]
    const critical = Math.random() > 0.96
    const entry = {
      _id: `sim-${Date.now()}`,
      timestamp: new Date(),
      sourceIp,
      destIp,
      protocol: ['HTTPS', 'TCP', 'DNS', 'UDP'][Math.floor(Math.random() * 4)],
      severity: critical ? 'CRITICAL' : Math.random() > 0.7 ? 'MEDIUM' : 'LOW',
      eventCategory: critical ? 'MALWARE_DETECTED' : ['AUTH_FAILURE', 'DNS_QUERY', 'POLICY_CHANGE'][Math.floor(Math.random() * 3)],
      rawPayload: 'Simulated telemetry event; no production sensor data is connected.',
      status: 'UNRESOLVED',
      networkZone,
      targetNode: { ...targetNode, isIsolated: false },
      mitreAttackTechnique: critical ? 'T1204 · User Execution' : 'T1071 · Application Layer Protocol',
    }
    io.emit('log:new', entry)
    if (critical) {
      try {
        const indicator = await ThreatIndicator.findOne({ value: { $in: [sourceIp, destIp] }, threatLevel: { $in: ['MALICIOUS', 'KNOWN_BAD'] } }).lean()
        if (indicator) io.emit('alert:critical', { message: `Critical event matched ${indicator.indicatorType} indicator ${indicator.value}`, entry, indicator })
      } catch (error) {
        console.error('Indicator correlation failed:', error)
      }
    }
    nextEmission = setTimeout(emitTelemetry, 3000 + Math.floor(Math.random() * 2001))
  }
  nextEmission = setTimeout(emitTelemetry, 3000 + Math.floor(Math.random() * 2001))
  return () => clearTimeout(nextEmission)
}