import type { NextFunction, Request, Response } from 'express'
import { getSimulationStatus, persistThreatBatch } from '../services/threatSimulator.service'

export function simulationStatus(_request: Request, response: Response) {
  response.json({ data: getSimulationStatus() })
}

export async function triggerSimulation(request: Request, response: Response, next: NextFunction) {
  try {
    const batch = await persistThreatBatch(request.app.get('io'))
    response.status(201).json({ data: batch })
  } catch (error) {
    next(error)
  }
}
