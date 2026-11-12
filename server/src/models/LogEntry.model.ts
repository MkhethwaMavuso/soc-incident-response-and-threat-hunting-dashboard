import { model, Schema, type InferSchemaType } from 'mongoose'

export const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const
export const LOG_STATUSES = ['UNRESOLVED', 'INVESTIGATING', 'MITIGATED', 'FALSE_POSITIVE'] as const
export const NETWORK_ZONES = ['INTRANET', 'EXTRANET', 'DMZ', 'CLOUD_VPC', 'REMOTE_ENDPOINT'] as const
export const NODE_TYPES = ['WORKSTATION', 'DATABASE_SERVER', 'WEB_GATEWAY', 'IOT_SENSOR', 'DOMAIN_CONTROLLER'] as const

const targetNodeSchema = new Schema({
  hostname: { type: String, required: true, trim: true, maxlength: 255 },
  ipAddress: { type: String, required: true, trim: true, maxlength: 64 },
  nodeType: { type: String, enum: NODE_TYPES, required: true },
  os: { type: String, required: true, trim: true, maxlength: 120 },
  isIsolated: { type: Boolean, default: false, required: true },
}, { _id: false, strict: 'throw' })

const logEntrySchema = new Schema({
  timestamp: { type: Date, default: Date.now, required: true, index: true },
  sourceIp: { type: String, required: true, trim: true, maxlength: 64, index: true },
  destIp: { type: String, required: true, trim: true, maxlength: 64 },
  protocol: { type: String, required: true, uppercase: true, trim: true, maxlength: 24 },
  severity: { type: String, enum: SEVERITIES, required: true, index: true },
  eventCategory: { type: String, required: true, trim: true, uppercase: true, maxlength: 80 },
  rawPayload: { type: String, required: true, maxlength: 16384 },
  status: { type: String, enum: LOG_STATUSES, default: 'UNRESOLVED', required: true },
  networkZone: { type: String, enum: NETWORK_ZONES, required: true, index: true },
  targetNode: { type: targetNodeSchema, required: true },
  mitreAttackTechnique: { type: String, default: '', trim: true, maxlength: 120 },
}, { timestamps: true, strict: 'throw' })

logEntrySchema.index({ timestamp: -1, severity: 1 })
logEntrySchema.index({ sourceIp: 1, timestamp: -1 })
logEntrySchema.index({ networkZone: 1, severity: 1, timestamp: -1 })

export type LogEntryDocument = InferSchemaType<typeof logEntrySchema>
export const LogEntry = model('LogEntry', logEntrySchema)