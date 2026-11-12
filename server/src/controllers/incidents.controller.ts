import mongoose from 'mongoose'
import type { Request, Response } from 'express'
import { z } from 'zod'
import { Incident, INCIDENT_STATUSES } from '../models/Incident.model'
import { NETWORK_ZONES, NODE_TYPES, SEVERITIES } from '../models/LogEntry.model'
import { User } from '../models/User.model'
import { broadcastIncidentUpdate } from '../utils/incidentBroadcast'
import { canEscalateIncident, incidentVisibilityFilter } from '../utils/incidentAccess'

const ESCALATION_ROLES = ['SOC_ANALYST_L1', 'THREAT_HUNTER_L2', 'INCIDENT_COMMANDER', 'CISO'] as const
const escalationNoteSchema = z.object({ note: z.string().trim().min(10).max(1000) }).strict()

const targetNodeSchema = z.object({
  hostname: z.string().min(1).max(255),
  ipAddress: z.string().min(1).max(64),
  nodeType: z.enum(NODE_TYPES),
  os: z.string().min(1).max(120),
  isIsolated: z.boolean().default(false),
}).strict()

const createSchema = z.object({
  title: z.string().trim().min(3).max(200),
  description: z.string().max(5000).optional(),
  severity: z.enum(SEVERITIES),
  networkZone: z.enum(NETWORK_ZONES).optional(),
  targetNode: targetNodeSchema.optional(),
  affectedHosts: z.array(z.string().trim().min(1).max(255)).max(100).optional(),
  mitreAttackTechnique: z.string().max(120).optional(),
}).strict()

export async function listIncidents(request: Request, response: Response) {
  const visibility = incidentVisibilityFilter(request.user!.role)
  const data = await Incident.find(visibility).sort({ createdAt: -1 }).limit(200).populate('assignedAnalyst', 'fullName email role').lean()
  response.json({
    data: data.map((incident) => ({
      ...incident,
      escalationRole: incident.escalationRole ?? 'SOC_ANALYST_L1',
      escalationHistory: incident.escalationHistory ?? [],
    })),
  })
}

export async function createIncident(request: Request, response: Response) {
  const input = createSchema.parse(request.body)
  const incident = await Incident.create({
    ...input,
    networkZone: input.networkZone ?? 'INTRANET',
    targetNode: input.targetNode ?? {
      hostname: input.affectedHosts?.[0] ?? 'UNKNOWN-HOST',
      ipAddress: '0.0.0.0',
      nodeType: 'WORKSTATION',
      os: 'Unknown',
      isIsolated: false,
    },
    timeline: [{ message: 'Incident created', author: request.user?.email ?? 'unknown' }],
  })
  broadcastIncidentUpdate(request.app.get('io'), incident)
  response.status(201).json({ data: incident })
}

export async function updateIncidentStatus(request: Request, response: Response) {
  const body = z.object({ status: z.enum(INCIDENT_STATUSES) }).strict().parse(request.body)
  const incidentId = request.params.id
  if (typeof incidentId !== 'string' || !mongoose.isValidObjectId(incidentId)) {
    response.status(400).json({ error: 'Invalid incident ID.' })
    return
  }
  if (body.status === 'RESOLVED' || body.status === 'CLOSED') {
    response.status(400).json({ error: 'Use the resolve action to close an incident with required resolution notes.' })
    return
  }
  const incident = await Incident.findOneAndUpdate({ _id: incidentId, ...incidentVisibilityFilter(request.user!.role) }, {
    $set: { status: body.status },
    $push: { timeline: { message: `Status changed to ${body.status}`, author: request.user?.email ?? 'unknown' } },
  }, { new: true, runValidators: true })
  if (!incident) {
    response.status(404).json({ error: 'Incident not found.' })
    return
  }
  broadcastIncidentUpdate(request.app.get('io'), incident)
  response.json({ data: incident })
}

export async function escalateIncident(request: Request, response: Response) {
  const { note } = escalationNoteSchema.parse(request.body)
  const incidentId = request.params.id
  if (typeof incidentId !== 'string' || !mongoose.isValidObjectId(incidentId)) {
    response.status(400).json({ error: 'Invalid incident ID.' })
    return
  }
  const current = await Incident.findOne({ _id: incidentId, ...incidentVisibilityFilter(request.user!.role) }).select('status escalationRole')
  if (!current) {
    response.status(404).json({ error: 'Incident not found.' })
    return
  }
  if (current.status === 'RESOLVED' || current.status === 'CLOSED') {
    response.status(409).json({ error: 'Resolved incidents cannot be escalated.' })
    return
  }
  const fromRole = current.escalationRole
  if (!canEscalateIncident(request.user!.role, fromRole)) {
    response.status(403).json({ error: 'You can only escalate an incident from your own tier.' })
    return
  }
  const nextRole = ESCALATION_ROLES[ESCALATION_ROLES.indexOf(fromRole) + 1]
  if (!nextRole) {
    response.status(409).json({ error: 'This incident is already at the highest escalation tier (CISO).' })
    return
  }

  const assignee = await User.findOne({ role: nextRole, status: 'ACTIVE' }).sort({ lastLogin: -1, createdAt: 1 }).select('_id').lean()
  const timestamp = new Date()
  const update: Record<string, unknown> = {
    $set: { escalationRole: nextRole, assignedAnalyst: assignee?._id ?? null },
    $push: {
      escalationHistory: { fromRole, toRole: nextRole, note, author: request.user?.email ?? 'unknown', timestamp },
      timeline: { message: `Escalated from ${fromRole} to ${nextRole}: ${note}`, author: request.user?.email ?? 'unknown', timestamp },
    },
  }
  const incident = await Incident.findOneAndUpdate(
    { _id: incidentId, escalationRole: fromRole, status: { $nin: ['RESOLVED', 'CLOSED'] } },
    update,
    { new: true, runValidators: true },
  ).populate('assignedAnalyst', 'fullName email role')
  if (!incident) {
    response.status(409).json({ error: 'The incident changed while escalation was being processed. Refresh and try again.' })
    return
  }
  broadcastIncidentUpdate(request.app.get('io'), incident, fromRole)
  response.json({ data: incident, message: `Escalated to ${nextRole}.` })
}

export async function resolveIncident(request: Request, response: Response) {
  const { note } = escalationNoteSchema.parse(request.body)
  const incidentId = request.params.id
  if (typeof incidentId !== 'string' || !mongoose.isValidObjectId(incidentId)) {
    response.status(400).json({ error: 'Invalid incident ID.' })
    return
  }
  const timestamp = new Date()
  const incident = await Incident.findOneAndUpdate(
    { _id: incidentId, ...incidentVisibilityFilter(request.user!.role), status: { $nin: ['RESOLVED', 'CLOSED'] } },
    {
      $set: { status: 'RESOLVED', resolutionNote: note, resolvedAt: timestamp },
      $push: { timeline: { message: `Resolved: ${note}`, author: request.user?.email ?? 'unknown', timestamp } },
    },
    { new: true, runValidators: true },
  ).populate('assignedAnalyst', 'fullName email role')
  if (!incident) {
    const exists = await Incident.exists({ _id: incidentId })
    response.status(exists ? 409 : 404).json({ error: exists ? 'This incident is already resolved or closed.' : 'Incident not found.' })
    return
  }
  broadcastIncidentUpdate(request.app.get('io'), incident)
  response.json({ data: incident, message: 'Incident resolved.' })
}