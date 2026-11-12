import { model, Schema, type InferSchemaType } from 'mongoose'

export const USER_ROLES = ['ADMIN', 'CISO', 'INCIDENT_COMMANDER', 'THREAT_HUNTER_L2', 'SOC_ANALYST_L1'] as const
export const USER_DEPARTMENTS = ['Threat Hunting', 'Incident Response', 'Network Security', 'Governance & Risk'] as const
export const USER_STATUSES = ['ACTIVE', 'SUSPENDED', 'ON_LEAVE'] as const

const userSchema = new Schema({
  fullName: { type: String, required: true, trim: true, maxlength: 120 },
  email: { type: String, required: true, trim: true, lowercase: true, unique: true, index: true },
  passwordHash: { type: String, required: true, select: false },
  badgeId: { type: String, required: true, trim: true, uppercase: true, unique: true, index: true },
  role: { type: String, enum: USER_ROLES, required: true, default: 'SOC_ANALYST_L1', index: true },
  department: { type: String, enum: USER_DEPARTMENTS, required: true },
  status: { type: String, enum: USER_STATUSES, default: 'ACTIVE', required: true, index: true },
  lastLogin: { type: Date },
  createdBy: { type: Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true, strict: 'throw' })

export type UserDocument = InferSchemaType<typeof userSchema>
export const User = model('User', userSchema)
