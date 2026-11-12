import type { Role } from '../types/security'

export type EscalationRole = Exclude<Role, 'ADMIN'>

export function canViewIncident(role: Role, escalationRole: EscalationRole) {
  return role === 'ADMIN' || role === 'INCIDENT_COMMANDER' || role === escalationRole
}

export function incidentVisibilityFilter(role: Role) {
  return role === 'ADMIN' || role === 'INCIDENT_COMMANDER' ? {} : { escalationRole: role }
}

export function canEscalateIncident(role: Role, escalationRole: EscalationRole) {
  return role === 'ADMIN' || role === escalationRole
}
