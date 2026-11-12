import type { Server } from 'socket.io'
import type { Role } from '../types/security'
import type { EscalationRole } from './incidentAccess'

export function broadcastIncidentUpdate(
  io: Server | undefined,
  incident: { _id: string | { toString(): string }; escalationRole?: EscalationRole },
  previousRole?: EscalationRole,
) {
  if (!io) return
  const escalationRole = incident.escalationRole ?? 'SOC_ANALYST_L1'
  const roles = new Set<Role>(['ADMIN', 'INCIDENT_COMMANDER', escalationRole])
  io.to([...roles].map((role) => `role:${role}`)).emit('incident:updated', incident)
  if (previousRole && !roles.has(previousRole)) {
    io.to(`role:${previousRole}`).emit('incident:updated', {
      _id: incident._id.toString(),
      escalationRole,
      accessRevoked: true,
    })
  }
}
