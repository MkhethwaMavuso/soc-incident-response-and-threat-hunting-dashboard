import type { Request, Response } from 'express'
import { z } from 'zod'
import { LogEntry, LOG_STATUSES, NETWORK_ZONES, NODE_TYPES, SEVERITIES } from '../models/LogEntry.model'

const targetNodeSchema = z.object({
  hostname: z.string().min(1).max(255),
  ipAddress: z.string().min(1).max(64),
  nodeType: z.enum(NODE_TYPES),
  os: z.string().min(1).max(120),
  isIsolated: z.boolean().default(false),
}).strict()

const ingestSchema = z.object({
  timestamp: z.coerce.date().optional(),
  sourceIp: z.string().min(1).max(64),
  destIp: z.string().min(1).max(64),
  protocol: z.string().min(1).max(24),
  severity: z.enum(SEVERITIES),
  eventCategory: z.string().min(1).max(80),
  rawPayload: z.string().max(16384),
  status: z.enum(LOG_STATUSES).optional(),
  networkZone: z.enum(NETWORK_ZONES).default('INTRANET'),
  targetNode: targetNodeSchema.optional(),
  mitreAttackTechnique: z.string().max(120).optional(),
})

export async function listLogs(request: Request, response: Response) {
  const filters: Record<string, unknown> = {}
  if (typeof request.query.severity === 'string' && SEVERITIES.includes(request.query.severity as typeof SEVERITIES[number])) filters.severity = request.query.severity
  if (typeof request.query.sourceIp === 'string') filters.sourceIp = request.query.sourceIp.slice(0, 64)
  if (typeof request.query.networkZone === 'string' && NETWORK_ZONES.includes(request.query.networkZone as typeof NETWORK_ZONES[number])) filters.networkZone = request.query.networkZone
  if (typeof request.query.from === 'string' || typeof request.query.to === 'string') {
    const timestamp: Record<string, Date> = {}
    if (typeof request.query.from === 'string' && !Number.isNaN(Date.parse(request.query.from))) timestamp.$gte = new Date(request.query.from)
    if (typeof request.query.to === 'string' && !Number.isNaN(Date.parse(request.query.to))) timestamp.$lte = new Date(request.query.to)
    if (Object.keys(timestamp).length) filters.timestamp = timestamp
  }
  const limit = Math.min(100, Math.max(1, Number(request.query.limit) || 50))
  const data = await LogEntry.find(filters).sort({ timestamp: -1 }).limit(limit).lean()
  response.json({ data })
}

export async function ingestLog(request: Request, response: Response) {
  const payload = ingestSchema.parse(request.body)
  const entry = await LogEntry.create({
    ...payload,
    targetNode: payload.targetNode ?? {
      hostname: payload.destIp,
      ipAddress: payload.destIp,
      nodeType: 'WORKSTATION',
      os: 'Unknown',
      isIsolated: false,
    },
  })
  const io = request.app.get('io')
  io?.emit('log:new', entry)
  response.status(201).json({ data: entry })
}