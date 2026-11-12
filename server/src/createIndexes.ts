import 'dotenv/config'
import mongoose from 'mongoose'
import { connectDatabase } from './config/database'
import { Incident } from './models/Incident.model'
import { LogEntry } from './models/LogEntry.model'
import { ThreatIndicator } from './models/ThreatIndicator.model'
import { User } from './models/User.model'
import { migrateLegacyDocuments } from './utils/seeder'

async function createIndexes() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required to provision database indexes.')
  await connectDatabase(process.env.MONGO_URI)
  await migrateLegacyDocuments()
  await Promise.all([User.createIndexes(), LogEntry.createIndexes(), Incident.createIndexes(), ThreatIndicator.createIndexes()])
  console.info('CyberShield SOC indexes are provisioned.')
  await mongoose.disconnect()
}

createIndexes().catch(async (error: unknown) => {
  console.error(error)
  await mongoose.disconnect()
  process.exitCode = 1
})