import mongoose from 'mongoose'
import type { Request, Response } from 'express'
import { z } from 'zod'
import { Incident } from '../models/Incident.model'
import { broadcastIncidentUpdate } from '../utils/incidentBroadcast'
import { incidentVisibilityFilter } from '../utils/incidentAccess'

const containmentSchema = z.object({
  host: z.string().trim().min(1).max(255),
  incidentId: z.string().optional(),
}).strict()

export async function simulateIsolation(request: Request, response: Response) {
  const { host, incidentId } = containmentSchema.parse(request.body)
  if (!incidentId || !mongoose.isValidObjectId(incidentId)) {
    response.status(400).json({ error: 'A valid incidentId is required for audited containment.' })
    return
  }
  const action = {
    actionTaken: `SIMULATED host isolation requested for ${host}; no endpoint action was executed.`,
    executedBy: request.user?.email ?? 'unknown',
    timestamp: new Date(),
  }
  const incident = await Incident.findOneAndUpdate({ _id: incidentId, ...incidentVisibilityFilter(request.user!.role) }, {
    $set: { status: 'CONTAINED', containmentAction: action },
    $push: { timeline: { message: action.actionTaken, author: action.executedBy, timestamp: action.timestamp } },
  }, { new: true, runValidators: true })
  if (!incident) {
    response.status(404).json({ error: 'Incident not found.' })
    return
  }
  broadcastIncidentUpdate(request.app.get('io'), incident)
  response.json({ data: incident, message: 'Simulation recorded. No endpoint or firewall action was executed.' })
}