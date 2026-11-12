import mongoose, { model, Schema, type InferSchemaType } from 'mongoose'
import { NETWORK_ZONES, NODE_TYPES, SEVERITIES } from './LogEntry.model'

export const INCIDENT_STATUSES = ['OPEN', 'CONTAINED', 'RESOLVED', 'CLOSED'] as const

const timelineSchema = new Schema({
  timestamp: { type: Date, default: Date.now, required: true },
  message: { type: String, required: true, trim: true, maxlength: 1000 },
  author: { type: String, required: true, trim: true, maxlength: 120 },
}, { _id: false, strict: 'throw' })

const containmentSchema = new Schema({
  actionTaken: { type: String, required: true, maxlength: 500 },
  executedBy: { type: String, required: true, maxlength: 120 },
  timestamp: { type: Date, default: Date.now, required: true },
}, { _id: false, strict: 'throw' })

const escalationSchema = new Schema({
  fromRole: { type: String, enum: ['SOC_ANALYST_L1', 'THREAT_HUNTER_L2', 'INCIDENT_COMMANDER', 'CISO'], required: true },
  toRole: { type: String, enum: ['SOC_ANALYST_L1', 'THREAT_HUNTER_L2', 'INCIDENT_COMMANDER', 'CISO'], required: true },
  note: { type: String, required: true, trim: true, maxlength: 1000 },
  author: { type: String, required: true, trim: true, maxlength: 254 },
  timestamp: { type: Date, default: Date.now, required: true },
}, { _id: false, strict: 'throw' })

const targetNodeSchema = new Schema({
  hostname: { type: String, required: true, trim: true, maxlength: 255 },
  ipAddress: { type: String, required: true, trim: true, maxlength: 64 },
  nodeType: { type: String, enum: NODE_TYPES, required: true },
  os: { type: String, required: true, trim: true, maxlength: 120 },
  isIsolated: { type: Boolean, default: false, required: true },
}, { _id: false, strict: 'throw' })

const incidentSchema = new Schema({
  title: { type: String, required: true, trim: true, maxlength: 200 },
  description: { type: String, default: '', maxlength: 5000 },
  severity: { type: String, enum: SEVERITIES, required: true },
  networkZone: { type: String, enum: NETWORK_ZONES, required: true, index: true },
  targetNode: { type: targetNodeSchema, required: true },
  timestamp: { type: Date, default: Date.now, required: true, index: true },
  status: { type: String, enum: INCIDENT_STATUSES, default: 'OPEN', required: true, index: true },
  assignedAnalyst: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  escalationRole: { type: String, enum: ['SOC_ANALYST_L1', 'THREAT_HUNTER_L2', 'INCIDENT_COMMANDER', 'CISO'], default: 'SOC_ANALYST_L1', required: true, index: true },
  escalationHistory: { type: [escalationSchema], default: [] },
  resolutionNote: { type: String, trim: true, maxlength: 1000 },
  resolvedAt: { type: Date },
  affectedHosts: { type: [{ type: String, trim: true, maxlength: 255 }], default: [] },
  mitreAttackTechnique: { type: String, default: '', trim: true, maxlength: 120 },
  containmentAction: { type: containmentSchema, default: undefined },
  timeline: { type: [timelineSchema], default: [] },
}, { timestamps: true, strict: 'throw' })

incidentSchema.index({ status: 1, severity: -1 })
incidentSchema.index({ createdAt: -1 })
incidentSchema.index({ networkZone: 1, severity: 1, timestamp: -1 })

export type IncidentDocument = InferSchemaType<typeof incidentSchema>
export const Incident = model('Incident', incidentSchema)