export type Role = 'ADMIN' | 'CISO' | 'INCIDENT_COMMANDER' | 'THREAT_HUNTER_L2' | 'SOC_ANALYST_L1'

export interface AccessTokenClaims {
  sub: string
  role: Role
  email: string
}