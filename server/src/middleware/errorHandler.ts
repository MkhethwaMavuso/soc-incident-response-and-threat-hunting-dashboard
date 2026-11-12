import type { ErrorRequestHandler } from 'express'
import { ZodError } from 'zod'

export const errorHandler: ErrorRequestHandler = (error, _request, response, _next) => {
  if (error instanceof ZodError) {
    response.status(400).json({ error: 'Invalid request.', details: error.flatten() })
    return
  }
  if (error?.name === 'ValidationError' || error?.name === 'CastError') {
    response.status(400).json({ error: 'Request data failed validation.' })
    return
  }
  if (error?.code === 11000) {
    response.status(409).json({ error: 'A record with that email or badge ID already exists.' })
    return
  }
  console.error(error)
  response.status(500).json({ error: 'Internal server error.' })
}