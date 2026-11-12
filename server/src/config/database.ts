import mongoose from 'mongoose'

export async function connectDatabase(uri: string | undefined) {
  if (!uri) {
    console.warn('MONGO_URI is not configured; database-backed API routes will be unavailable.')
    return
  }
  mongoose.set('strictQuery', true)
  await mongoose.connect(uri, { autoIndex: process.env.NODE_ENV !== 'production' })
  console.info('Connected to MongoDB.')
}