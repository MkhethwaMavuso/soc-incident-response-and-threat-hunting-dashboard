import { Router } from 'express'
import rateLimit from 'express-rate-limit'
import { login, currentUser } from '../controllers/auth.controller'
import { simulateBlacklist } from '../controllers/blacklist.controller'
import { simulateIsolation } from '../controllers/containment.controller'
import { createIncident, escalateIncident, listIncidents, resolveIncident, updateIncidentStatus } from '../controllers/incidents.controller'
import { ingestLog, listLogs } from '../controllers/logs.controller'
import { createIndicator, listIndicators } from '../controllers/threatIndicators.controller'
import { simulationStatus, triggerSimulation } from '../controllers/simulation.controller'
import { asyncHandler } from '../middleware/asyncHandler'
import { authenticate, authorize } from '../middleware/auth'
import staffRouter from './staff.routes'

const router = Router()
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false })

router.post('/auth/login', loginLimiter, asyncHandler(login))
router.get('/health', (_request, response) => response.json({ status: 'ok', database: 'managed by MongoDB connection' }))
router.use(asyncHandler(authenticate))
router.get('/auth/me', asyncHandler(currentUser))
router.use('/staff', staffRouter)
router.get('/simulation/status', simulationStatus)
router.post('/simulation/trigger-now', authorize('ADMIN'), asyncHandler(triggerSimulation))
router.get('/logs', asyncHandler(listLogs))
router.post('/logs', asyncHandler(ingestLog))
router.get('/incidents', asyncHandler(listIncidents))
router.post('/incidents', asyncHandler(createIncident))
router.patch('/incidents/:id/status', asyncHandler(updateIncidentStatus))
router.post('/incidents/:id/escalate', asyncHandler(escalateIncident))
router.post('/incidents/:id/resolve', asyncHandler(resolveIncident))
router.get('/threat-indicators', asyncHandler(listIndicators))
router.post('/threat-indicators', authorize('ADMIN', 'THREAT_HUNTER_L2', 'INCIDENT_COMMANDER'), asyncHandler(createIndicator))
router.post('/containment/isolate', authorize('ADMIN', 'THREAT_HUNTER_L2', 'INCIDENT_COMMANDER'), asyncHandler(simulateIsolation))
router.post('/containment/blacklist', authorize('ADMIN', 'THREAT_HUNTER_L2', 'INCIDENT_COMMANDER'), asyncHandler(simulateBlacklist))

export default router