import mongoose from 'mongoose'
import type { Request, Response } from 'express'
import { z } from 'zod'
import { Incident } from '../models/Incident.model'
import { broadcastIncidentUpdate } from '../utils/incidentBroadcast'
import { incidentVisibilityFilter } from '../utils/incidentAccess'

const blacklistSchema = z.object({
  indicator: z.string().trim().min(1).max(2048),
  incidentId: z.string().min(1),
}).strict()

export async function simulateBlacklist(request: Request, response: Response) {
  const { indicator, incidentId } = blacklistSchema.parse(request.body)
  if (!mongoose.isValidObjectId(incidentId)) {
    response.status(400).json({ error: 'A valid incidentId is required for an audited network action.' })
    return
  }
  const author = request.user?.email ?? 'unknown'
  const message = `SIMULATED network blacklist requested for ${indicator}; no firewall or network policy was changed.`
  const incident = await Incident.findOneAndUpdate({ _id: incidentId, ...incidentVisibilityFilter(request.user!.role) }, {
    $push: { timeline: { message, author, timestamp: new Date() } },
  }, { new: true, runValidators: true })
  if (!incident) {
    response.status(404).json({ error: 'Incident not found.' })
    return
  }
  broadcastIncidentUpdate(request.app.get('io'), incident)
  response.json({ data: incident, message: 'Simulation recorded. No firewall or network policy was changed.' })
}