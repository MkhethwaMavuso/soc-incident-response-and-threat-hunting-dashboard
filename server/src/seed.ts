import 'dotenv/config'
import mongoose from 'mongoose'
import { connectDatabase } from './config/database'
import { seedDatabase } from './utils/seeder'

async function seed() {
  await connectDatabase(process.env.MONGO_URI)
  if (mongoose.connection.readyState !== 1) throw new Error('MONGO_URI is required to seed the database.')
  await seedDatabase()
  await mongoose.disconnect()
}

seed().catch(async (error: unknown) => {
  console.error(error)
  await mongoose.disconnect()
  process.exitCode = 1
})
