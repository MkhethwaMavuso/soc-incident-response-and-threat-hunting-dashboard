import 'dotenv/config'
import http from 'node:http'
import cors from 'cors'
import express from 'express'
import helmet from 'helmet'
import mongoose from 'mongoose'
import { Server } from 'socket.io'
import { connectDatabase } from './config/database'
import { errorHandler } from './middleware/errorHandler'
import apiRouter from './routes/api'
import { registerSocketHandlers } from './sockets'
import { seedDatabase } from './utils/seeder'
import { startThreatSimulator } from './services/threatSimulator.service'

const app = express()
const server = http.createServer(app)
const origins = (process.env.CLIENT_ORIGIN ?? 'http://localhost:5173').split(',').map((origin) => origin.trim())
const io = new Server(server, { cors: { origin: origins, methods: ['GET', 'POST', 'PATCH', 'DELETE'] } })
const port = Number(process.env.PORT) || 4000

app.set('io', io)
app.disable('x-powered-by')
app.use(helmet())
app.use(cors({ origin: origins, methods: ['GET', 'POST', 'PATCH', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization'] }))
app.use(express.json({ limit: '128kb' }))
app.use('/api', apiRouter)
app.use(errorHandler)

async function start() {
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must contain at least 32 characters.')
  await connectDatabase(process.env.MONGO_URI)
  mongoose.connection.on('error', (error) => console.error('MongoDB connection error:', error.message))
  if (mongoose.connection.readyState === 1) await seedDatabase()
  const stopTelemetry = registerSocketHandlers(io)
  const stopThreatSimulation = mongoose.connection.readyState === 1 ? startThreatSimulator(io) : () => undefined
  server.listen(port, '0.0.0.0', () => console.info(`CyberShield SOC API listening on ${port}`))
  const shutdown = () => {
    stopTelemetry()
    stopThreatSimulation()
    io.close()
    server.close(() => { void mongoose.disconnect().finally(() => process.exit(0)) })
  }
  process.once('SIGINT', shutdown)
  process.once('SIGTERM', shutdown)
}

start().catch((error: unknown) => {
  console.error('Failed to start CyberShield SOC API:', error)
  process.exitCode = 1
})