import { model, Schema, type InferSchemaType } from 'mongoose'

export const INDICATOR_TYPES = ['IP', 'DOMAIN', 'HASH_SHA256', 'URL'] as const
export const THREAT_LEVELS = ['SUSPICIOUS', 'MALICIOUS', 'KNOWN_BAD'] as const

const threatIndicatorSchema = new Schema({
  indicatorType: { type: String, enum: INDICATOR_TYPES, required: true },
  value: { type: String, required: true, trim: true, maxlength: 2048 },
  threatLevel: { type: String, enum: THREAT_LEVELS, required: true },
  confidenceScore: { type: Number, min: 0, max: 100, default: 50 },
  firstSeen: { type: Date, default: Date.now, required: true },
  tags: { type: [{ type: String, trim: true, maxlength: 80 }], default: [] },
}, { timestamps: true, strict: 'throw' })

threatIndicatorSchema.index({ value: 1 }, { unique: true })
threatIndicatorSchema.index({ indicatorType: 1, threatLevel: 1 })

export type ThreatIndicatorDocument = InferSchemaType<typeof threatIndicatorSchema>
export const ThreatIndicator = model('ThreatIndicator', threatIndicatorSchema)