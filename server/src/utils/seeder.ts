import { randomBytes } from 'node:crypto'
import bcrypt from 'bcryptjs'
import { Incident } from '../models/Incident.model'
import { LogEntry } from '../models/LogEntry.model'
import { User } from '../models/User.model'
import { persistThreatBatch } from '../services/threatSimulator.service'

export async function seedDatabase() {
  await migrateLegacyDocuments()
  const adminCount = await User.countDocuments({ role: 'ADMIN' })
  if (adminCount === 0) {
    const email = (process.env.SOC_ADMIN_EMAIL ?? 'admin@cybershield.io').toLowerCase()
    const existing = await User.findOne({ email }).select('+passwordHash')
    if (existing) {
      existing.role = 'ADMIN'
      existing.status = 'ACTIVE'
      await existing.save()
      console.info(`Configured account ${email} promoted to ADMIN.`)
    } else {
      const generatedPassword = process.env.SOC_ADMIN_PASSWORD ? undefined : randomBytes(24).toString('base64url')
      const password = process.env.SOC_ADMIN_PASSWORD ?? generatedPassword
      if (!password || password.length < 14) throw new Error('SOC_ADMIN_PASSWORD must contain at least 14 characters.')
      await User.create({
        fullName: process.env.SOC_ADMIN_NAME ?? 'SOC Administrator',
        email,
        passwordHash: await bcrypt.hash(password, 12),
        badgeId: process.env.SOC_ADMIN_BADGE_ID ?? 'SOC-0001',
        role: 'ADMIN',
        department: 'Governance & Risk',
        status: 'ACTIVE',
      })
      if (generatedPassword) {
        console.warn(`Initial admin account created for ${email}. Set SOC_ADMIN_PASSWORD to a private value before deployment. One-time password: ${generatedPassword}`)
      } else {
        console.info(`Initial admin account created for ${email}.`)
      }
    }
  }

  if (await LogEntry.countDocuments() === 0) {
    const { logs, incidents } = await persistThreatBatch(undefined, 50)
    console.info(`Seeded ${logs.length} synthetic network events and ${incidents.length} critical incident(s).`)
  }
}

export async function migrateLegacyDocuments() {
  await Incident.collection.updateMany(
    { $or: [{ escalationRole: { $exists: false } }, { escalationHistory: { $exists: false } }] },
    [{
      $set: {
        escalationRole: { $ifNull: ['$escalationRole', 'SOC_ANALYST_L1'] },
        escalationHistory: { $ifNull: ['$escalationHistory', []] },
      },
    }],
  )
  await User.collection.updateMany(
    { $or: [{ fullName: { $exists: false } }, { badgeId: { $exists: false } }, { department: { $exists: false } }, { status: { $exists: false } }] },
    [
      { $set: {
        fullName: { $ifNull: ['$fullName', { $ifNull: ['$name', 'SOC Staff'] }] },
        badgeId: { $ifNull: ['$badgeId', { $concat: ['SOC-', { $toUpper: { $toString: '$_id' } }] }] },
        department: { $ifNull: ['$department', 'Incident Response'] },
        status: { $ifNull: ['$status', { $cond: [{ $eq: ['$active', false] }, 'SUSPENDED', 'ACTIVE'] }] },
      } },
      { $unset: ['name', 'active'] },
    ],
  )
  await LogEntry.collection.updateMany(
    { $or: [{ networkZone: { $exists: false } }, { targetNode: { $exists: false } }] },
    [{ $set: {
      networkZone: { $ifNull: ['$networkZone', 'INTRANET'] },
      targetNode: { $ifNull: ['$targetNode', {
        hostname: { $ifNull: ['$destIp', 'UNKNOWN-HOST'] },
        ipAddress: { $ifNull: ['$destIp', '0.0.0.0'] },
        nodeType: 'WORKSTATION',
        os: 'Unknown',
        isIsolated: false,
      }] },
      mitreAttackTechnique: { $ifNull: ['$mitreAttackTechnique', ''] },
    } }],
  )
  await Incident.collection.updateMany(
    { $or: [{ networkZone: { $exists: false } }, { targetNode: { $exists: false } }, { timestamp: { $exists: false } }] },
    [{ $set: {
      networkZone: { $ifNull: ['$networkZone', 'INTRANET'] },
      targetNode: { $ifNull: ['$targetNode', {
        hostname: { $ifNull: [{ $arrayElemAt: ['$affectedHosts', 0] }, 'UNKNOWN-HOST'] },
        ipAddress: '0.0.0.0',
        nodeType: 'WORKSTATION',
        os: 'Unknown',
        isIsolated: false,
      }] },
      timestamp: { $ifNull: ['$timestamp', '$createdAt'] },
    } }],
  )
}
