import type { Request, Response } from 'express'
import { z } from 'zod'
import { INDICATOR_TYPES, THREAT_LEVELS, ThreatIndicator } from '../models/ThreatIndicator.model'

const indicatorSchema = z.object({
  indicatorType: z.enum(INDICATOR_TYPES),
  value: z.string().trim().min(1).max(2048),
  threatLevel: z.enum(THREAT_LEVELS),
  confidenceScore: z.number().min(0).max(100).default(50),
  tags: z.array(z.string().trim().max(80)).max(30).default([]),
}).strict()

export async function listIndicators(_request: Request, response: Response) {
  const data = await ThreatIndicator.find().sort({ firstSeen: -1 }).limit(500).lean()
  response.json({ data })
}

export async function createIndicator(request: Request, response: Response) {
  const indicator = await ThreatIndicator.create(indicatorSchema.parse(request.body))
  response.status(201).json({ data: indicator })
}