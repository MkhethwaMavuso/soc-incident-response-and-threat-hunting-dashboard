import type { NextFunction, Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import { User } from '../models/User.model'
import type { AccessTokenClaims, Role } from '../types/security'

export async function authenticate(request: Request, response: Response, next: NextFunction) {
  const [scheme, token] = (request.headers.authorization ?? '').split(' ')
  if (scheme !== 'Bearer' || !token) {
    response.status(401).json({ error: 'Authentication required.' })
    return
  }
  try {
    const claims = jwt.verify(token, requiredSecret()) as jwt.JwtPayload & AccessTokenClaims
    const user = await User.findById(claims.sub).select('email role status')
    if (!user || user.status !== 'ACTIVE') {
      response.status(401).json({ error: 'User account is no longer active.' })
      return
    }
    request.user = { id: user.id, role: user.role as Role, email: user.email }
    next()
  } catch (error) {
    if (error instanceof Error && ['JsonWebTokenError', 'TokenExpiredError'].includes(error.name)) {
      response.status(401).json({ error: 'Invalid or expired access token.' })
      return
    }
    next(error)
  }
}

export function requireRole(...allowedRoles: Role[]) {
  return (request: Request, response: Response, next: NextFunction) => {
    if (!request.user || !allowedRoles.includes(request.user.role)) {
      response.status(403).json({ error: 'Insufficient clearance for this action.' })
      return
    }
    next()
  }
}

export const authorize = requireRole

export function requiredSecret() {
  const secret = process.env.JWT_SECRET
  if (!secret || secret.length < 32) throw new Error('JWT_SECRET must be set to at least 32 characters.')
  return secret
}