import type { Role } from './security'

declare global {
  namespace Express {
    interface Request {
      user?: { id: string; role: Role; email: string }
    }
  }
}

export {}