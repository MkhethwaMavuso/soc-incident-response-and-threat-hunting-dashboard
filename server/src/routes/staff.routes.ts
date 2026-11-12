import { Router } from 'express'
import { createStaff, deleteStaff, listStaff, updateStaff } from '../controllers/staff.controller'
import { asyncHandler } from '../middleware/asyncHandler'
import { requireRole } from '../middleware/auth'

const router = Router()
router.use(requireRole('ADMIN'))
router.get('/', asyncHandler(listStaff))
router.post('/', asyncHandler(createStaff))
router.patch('/:id', asyncHandler(updateStaff))
router.delete('/:id', asyncHandler(deleteStaff))

export default router
