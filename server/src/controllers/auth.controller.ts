import bcrypt from 'bcryptjs'
import type { Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import { z } from 'zod'
import { User } from '../models/User.model'
import { requiredSecret } from '../middleware/auth'

const loginSchema = z.object({ email: z.string().email().max(254), password: z.string().min(1).max(200) })

export async function login(request: Request, response: Response) {
  const { email, password } = loginSchema.parse(request.body)
  const user = await User.findOne({ email: email.toLowerCase(), status: 'ACTIVE' }).select('+passwordHash')
  const passwordMatches = user ? await bcrypt.compare(password, user.passwordHash) : false
  if (!user || !passwordMatches) {
    response.status(401).json({ error: 'Invalid email or password.' })
    return
  }
  user.lastLogin = new Date()
  await user.save()
  const token = jwt.sign({ role: user.role, email: user.email }, requiredSecret(), { subject: user.id })
  response.json({ data: { token, user: { id: user.id, name: user.fullName, fullName: user.fullName, email: user.email, role: user.role } } })
}

export async function currentUser(request: Request, response: Response) {
  const user = await User.findById(request.user?.id).select('fullName email role status')
  if (!user || user.status !== 'ACTIVE') {
    response.status(401).json({ error: 'User is no longer active.' })
    return
  }
  response.json({ data: { id: user.id, name: user.fullName, fullName: user.fullName, email: user.email, role: user.role } })
}