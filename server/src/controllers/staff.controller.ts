import bcrypt from 'bcryptjs'
import mongoose from 'mongoose'
import type { Request, Response } from 'express'
import type { Server } from 'socket.io'
import { z } from 'zod'
import { User, USER_DEPARTMENTS, USER_ROLES, USER_STATUSES } from '../models/User.model'

const staffFields = {
  fullName: z.string().trim().min(2).max(120),
  email: z.string().trim().email().max(254).transform((value) => value.toLowerCase()),
  badgeId: z.string().trim().min(3).max(32).transform((value) => value.toUpperCase()),
  role: z.enum(USER_ROLES),
  department: z.enum(USER_DEPARTMENTS),
  status: z.enum(USER_STATUSES),
}
const createStaffSchema = z.object({ ...staffFields, password: z.string().min(14).max(200) }).strict()
const updateStaffSchema = z.object({ ...staffFields, password: z.string().min(14).max(200).optional() }).partial().strict()

export async function listStaff(request: Request, response: Response) {
  const filters: Record<string, unknown> = {}
  if (typeof request.query.role === 'string' && USER_ROLES.includes(request.query.role as typeof USER_ROLES[number])) filters.role = request.query.role
  if (typeof request.query.status === 'string' && USER_STATUSES.includes(request.query.status as typeof USER_STATUSES[number])) filters.status = request.query.status
  if (typeof request.query.department === 'string' && USER_DEPARTMENTS.includes(request.query.department as typeof USER_DEPARTMENTS[number])) filters.department = request.query.department
  if (typeof request.query.search === 'string' && request.query.search.trim()) {
    const search = request.query.search.trim().slice(0, 100).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    filters.$or = [
      { fullName: { $regex: search, $options: 'i' } },
      { email: { $regex: search, $options: 'i' } },
      { badgeId: { $regex: search, $options: 'i' } },
    ]
  }
  const data = await User.find(filters).select('-passwordHash').sort({ fullName: 1 }).limit(250).lean()
  response.json({ data })
}

export async function createStaff(request: Request, response: Response) {
  const input = createStaffSchema.parse(request.body)
  const { password, ...fields } = input
  const staff = await User.create({
    ...fields,
    passwordHash: await bcrypt.hash(password, 12),
    createdBy: request.user?.id,
  })
  request.app.get('io')?.to('role:ADMIN').emit('staff:updated')
  const { passwordHash: _passwordHash, ...data } = staff.toObject()
  response.status(201).json({ data })
}

export async function updateStaff(request: Request, response: Response) {
  const staffId = request.params.id
  if (typeof staffId !== 'string' || !mongoose.isValidObjectId(staffId)) {
    response.status(400).json({ error: 'Invalid staff member ID.' })
    return
  }
  const input = updateStaffSchema.parse(request.body)
  const { password, ...fields } = input
  const updates: Record<string, unknown> = { ...fields }
  if (password) updates.passwordHash = await bcrypt.hash(password, 12)
  const staff = await User.findByIdAndUpdate(staffId, { $set: updates }, {
    new: true, runValidators: true, select: '-passwordHash',
  }).lean()
  if (!staff) {
    response.status(404).json({ error: 'Staff member not found.' })
    return
  }
  await disconnectStaffSessions(request, staff._id.toString())
  request.app.get('io')?.to('role:ADMIN').emit('staff:updated')
  response.json({ data: staff })
}

export async function deleteStaff(request: Request, response: Response) {
  const staffId = request.params.id
  if (typeof staffId !== 'string' || !mongoose.isValidObjectId(staffId)) {
    response.status(400).json({ error: 'Invalid staff member ID.' })
    return
  }
  if (request.user?.id && new mongoose.Types.ObjectId(staffId).equals(request.user.id)) {
    response.status(409).json({ error: 'You cannot delete your own active administrator account.' })
    return
  }
  const staff = await User.findByIdAndDelete(staffId).select('-passwordHash').lean()
  if (!staff) {
    response.status(404).json({ error: 'Staff member not found.' })
    return
  }
  await disconnectStaffSessions(request, staff._id.toString())
  request.app.get('io')?.to('role:ADMIN').emit('staff:updated')
  response.json({ data: { id: staff._id, deleted: true } })
}

async function disconnectStaffSessions(request: Request, staffId: string) {
  const io = request.app.get('io') as Server | undefined
  if (!io) return
  const sockets = await io.fetchSockets()
  for (const socket of sockets) {
    if (socket.data.user?.sub === staffId) socket.disconnect(true)
  }
}
