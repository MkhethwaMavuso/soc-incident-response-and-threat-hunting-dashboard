import { randomInt } from 'node:crypto'
import type { Server } from 'socket.io'
import { Incident } from '../models/Incident.model'
import { LogEntry, NETWORK_ZONES, NODE_TYPES, SEVERITIES } from '../models/LogEntry.model'
import type { Role } from '../types/security'
import { broadcastIncidentUpdate } from '../utils/incidentBroadcast'

const SIMULATION_INTERVAL_MS = 60 * 60 * 1000
const ESCALATION_TIERS = ['SOC_ANALYST_L1', 'THREAT_HUNTER_L2', 'INCIDENT_COMMANDER', 'CISO'] as const
const SCHEDULED_INCIDENT_TIERS = ['SOC_ANALYST_L1', 'THREAT_HUNTER_L2'] as const
const hosts = [
  { hostname: 'FIN-WS-042', ipAddress: '10.24.8.42', nodeType: 'WORKSTATION', os: 'Windows 11', networkZone: 'INTRANET' },
  { hostname: 'EXT-GW-01', ipAddress: '203.0.113.18', nodeType: 'WEB_GATEWAY', os: 'Linux', networkZone: 'EXTRANET' },
  { hostname: 'DMZ-WEB-01', ipAddress: '10.28.1.10', nodeType: 'WEB_GATEWAY', os: 'Linux', networkZone: 'DMZ' },
  { hostname: 'IOT-SENSOR-14', ipAddress: '10.40.2.14', nodeType: 'IOT_SENSOR', os: 'Embedded Linux', networkZone: 'REMOTE_ENDPOINT' },
  { hostname: 'PROD-DB-03', ipAddress: '10.32.4.23', nodeType: 'DATABASE_SERVER', os: 'Ubuntu 24.04', networkZone: 'CLOUD_VPC' },
  { hostname: 'IDP-CORE-01', ipAddress: '10.24.0.12', nodeType: 'DOMAIN_CONTROLLER', os: 'Windows Server 2022', networkZone: 'INTRANET' },
] as const
const scenarios = [
  { eventCategory: 'LATERAL_MOVEMENT', protocol: 'TCP', technique: 'T1021 · Remote Services', summary: 'Synthetic east-west authentication anomaly; no connection was initiated.' },
  { eventCategory: 'GATEWAY_REQUEST_ANOMALY', protocol: 'HTTPS', technique: 'T1190 · Exploit Public-Facing Application', summary: 'Synthetic gateway request pattern flagged for analyst review.' },
  { eventCategory: 'SUSPICIOUS_ATTACHMENT', protocol: 'SMTP', technique: 'T1566.001 · Spearphishing Attachment', summary: 'Synthetic attachment reputation alert; no file was created or delivered.' },
  { eventCategory: 'UNUSUAL_DATA_ACCESS', protocol: 'TLS', technique: 'T1005 · Data from Local System', summary: 'Synthetic access pattern exceeded the node baseline.' },
  { eventCategory: 'REMOTE_LOGIN_ANOMALY', protocol: 'SSH', technique: 'T1021.004 · SSH', summary: 'Synthetic remote sign-in pattern requires triage.' },
] as const
const zoneChoices = [...NETWORK_ZONES]
function choose<T>(items: readonly T[]): T {
  return items[randomInt(items.length)]
}

function generateRecord(preferredZone?: typeof NETWORK_ZONES[number]) {
  const eligibleHosts = preferredZone ? hosts.filter((host) => host.networkZone === preferredZone) : hosts
  const host = choose(eligibleHosts)
  const scenario = choose(scenarios)
  const { networkZone, ...node } = host
  const severity = choose(SEVERITIES)
  return {
    timestamp: new Date(),
    sourceIp: `198.51.100.${randomInt(10, 240)}`,
    destIp: host.ipAddress,
    protocol: scenario.protocol,
    severity,
    eventCategory: scenario.eventCategory,
    rawPayload: `${scenario.summary} [SIMULATION ONLY]`,
    status: 'UNRESOLVED' as const,
    networkZone,
    targetNode: { ...node, isIsolated: false, nodeType: node.nodeType as typeof NODE_TYPES[number] },
    mitreAttackTechnique: scenario.technique,
  }
}

export async function persistThreatBatch(
  io: Server | undefined,
  count = 5,
  incidentsPerTier = 0,
  incidentTiers: readonly Exclude<Role, 'ADMIN'>[] = ESCALATION_TIERS,
) {
  const tieredIncidentCount = incidentTiers.length * incidentsPerTier
  const recordCount = Math.max(count, tieredIncidentCount)
  const records = Array.from({ length: recordCount }, (_, index) => generateRecord(
    recordCount >= 50 ? zoneChoices[index % zoneChoices.length] : undefined,
  ))
  if (recordCount >= 50 && !records.some((record) => record.severity === 'CRITICAL')) records[0].severity = 'CRITICAL'
  const logs = await LogEntry.insertMany(records)
  const incidentInputs = logs.flatMap((log, index) => {
    const isTieredIncident = index < tieredIncidentCount
    if (!isTieredIncident && log.severity !== 'CRITICAL') return []
    const escalationRole = isTieredIncident
      ? incidentTiers[Math.floor(index / incidentsPerTier)]
      : 'SOC_ANALYST_L1'
    return [{
      title: `Simulated ${log.eventCategory.replaceAll('_', ' ').toLowerCase()} alert`,
      description: `${log.rawPayload} Network telemetry simulation; no external activity occurred.`,
      severity: log.severity,
      networkZone: log.networkZone,
      targetNode: log.targetNode,
      timestamp: log.timestamp,
      escalationRole,
      affectedHosts: [log.targetNode.hostname, log.targetNode.ipAddress],
      mitreAttackTechnique: log.mitreAttackTechnique,
      timeline: [{ timestamp: log.timestamp, message: `Automated simulation assigned to ${escalationRole}`, author: 'Threat simulation engine' }],
    }]
  })
  const incidents = incidentInputs.length ? await Incident.insertMany(incidentInputs) : []

  const batch = { logs, incidents, generatedAt: new Date().toISOString() }
  if (io) {
    const roles: Role[] = ['ADMIN', 'INCIDENT_COMMANDER', 'SOC_ANALYST_L1', 'THREAT_HUNTER_L2', 'CISO']
    for (const role of roles) {
      const visibleIncidents = role === 'ADMIN' || role === 'INCIDENT_COMMANDER'
        ? incidents
        : incidents.filter((incident) => incident.escalationRole === role)
      io.to(`role:${role}`).emit('threat:new_batch', { ...batch, incidents: visibleIncidents })
    }
    for (const log of logs) io.emit('log:new', log)
    for (const incident of incidents) broadcastIncidentUpdate(io, incident)
  }
  return batch
}

let nextRunAt: Date | null = null
let scheduledRun: NodeJS.Timeout | undefined
let stopped = true
let batchRunning = false

export function getSimulationStatus() {
  return { active: !stopped, intervalMs: SIMULATION_INTERVAL_MS, nextRunAt: nextRunAt?.toISOString() ?? null }
}

export function startThreatSimulator(io: Server) {
  if (!stopped) return () => stopThreatSimulator()
  stopped = false
  const runScheduledBatch = async () => {
    if (stopped || batchRunning) return
    batchRunning = true
    try {
      const batch = await persistThreatBatch(io, 10, 5, SCHEDULED_INCIDENT_TIERS)
      console.info(`Scheduled threat simulation created ${batch.incidents.length} incidents.`)
    } catch (error) {
      console.error('Scheduled threat simulation failed:', error)
    } finally {
      batchRunning = false
      if (!stopped) nextRunAt = new Date(Date.now() + SIMULATION_INTERVAL_MS)
    }
  }
  nextRunAt = new Date()
  void runScheduledBatch()
  scheduledRun = setInterval(() => { void runScheduledBatch() }, SIMULATION_INTERVAL_MS)
  scheduledRun.unref()
  return () => stopThreatSimulator()
}

export function stopThreatSimulator() {
  stopped = true
  if (scheduledRun) clearInterval(scheduledRun)
  scheduledRun = undefined
  nextRunAt = null
}
