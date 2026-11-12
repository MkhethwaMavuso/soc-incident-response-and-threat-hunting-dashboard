import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { CirclePlus, LockKeyhole, Pencil, Search, ShieldCheck, Trash2, Users, X } from 'lucide-react'
import { api } from '../services/api'
import { useSocket } from '../context/SocketContext'
import type { Department, Role, StaffMember, StaffStatus } from '../types'

const roles: Role[] = ['ADMIN', 'CISO', 'INCIDENT_COMMANDER', 'THREAT_HUNTER_L2', 'SOC_ANALYST_L1']
const departments: Department[] = ['Threat Hunting', 'Incident Response', 'Network Security', 'Governance & Risk']
const roleTitles: Record<Role, string> = {
  ADMIN: 'Administrator',
  CISO: 'CISO',
  INCIDENT_COMMANDER: 'Incident Commander',
  THREAT_HUNTER_L2: 'Threat Hunter · L2',
  SOC_ANALYST_L1: 'SOC Analyst · L1',
}
const roleClass: Record<Role, string> = {
  ADMIN: 'role-admin',
  CISO: 'role-violet',
  INCIDENT_COMMANDER: 'role-amber',
  THREAT_HUNTER_L2: 'role-blue',
  SOC_ANALYST_L1: 'role-green',
}
const permissionRows: { role: Role; permissions: string }[] = [
  { role: 'SOC_ANALYST_L1', permissions: 'View telemetry · Triage alerts · Escalate incidents' },
  { role: 'THREAT_HUNTER_L2', permissions: 'Threat hunt · Manage indicators · Block indicators' },
  { role: 'INCIDENT_COMMANDER', permissions: 'Coordinate response · Approve host isolation' },
  { role: 'CISO', permissions: 'Read-only security and risk oversight' },
  { role: 'ADMIN', permissions: 'Full system access · Staff and RBAC management' },
]

interface StaffFormState {
  fullName: string
  email: string
  badgeId: string
  role: Role
  department: Department
  status: StaffStatus
  password: string
}

const emptyForm: StaffFormState = {
  fullName: '',
  email: '',
  badgeId: '',
  role: 'SOC_ANALYST_L1',
  department: 'Threat Hunting',
  status: 'ACTIVE',
  password: '',
}

export function StaffManagement({ onNotify }: { onNotify: (message: string) => void }) {
  const [staff, setStaff] = useState<StaffMember[]>([])
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [editing, setEditing] = useState<StaffMember | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [deleting, setDeleting] = useState<StaffMember | null>(null)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState('')
  const { socket } = useSocket()

  const loadStaff = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const { data } = await api.get<{ data: StaffMember[] }>('/staff')
      setStaff(data.data)
    } catch {
      setError('Unable to load staff directory. Check your admin session and API connection.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadStaff()
    socket.on('staff:updated', loadStaff)
    return () => { socket.off('staff:updated', loadStaff) }
  }, [socket, loadStaff])

  const visibleStaff = useMemo(() => staff.filter((member) => {
    const matchesText = `${member.fullName} ${member.email} ${member.badgeId}`.toLowerCase().includes(search.toLowerCase())
    return matchesText
      && (roleFilter === 'ALL' || member.role === roleFilter)
      && (statusFilter === 'ALL' || member.status === statusFilter)
  }), [staff, search, roleFilter, statusFilter])

  function openCreate() {
    setEditing(null)
    setFormError('')
    setFormOpen(true)
  }

  function openEdit(member: StaffMember) {
    setEditing(member)
    setFormError('')
    setFormOpen(true)
  }

  async function saveStaff(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const formData = new FormData(event.currentTarget)
    const payload: Record<string, string> = {
      fullName: String(formData.get('fullName')).trim(),
      email: String(formData.get('email')).trim(),
      badgeId: String(formData.get('badgeId')).trim(),
      role: String(formData.get('role')),
      department: String(formData.get('department')),
      status: String(formData.get('status')),
    }
    const password = String(formData.get('password'))
    if (password) payload.password = password
    if (!editing && !password) {
      setFormError('An initial password is required for new staff accounts.')
      return
    }
    setSaving(true)
    setFormError('')
    try {
      if (editing) await api.patch(`/staff/${editing._id}`, payload)
      else await api.post('/staff', payload)
      setFormOpen(false)
      await loadStaff()
      onNotify(editing ? 'Staff profile updated.' : 'Staff account created.')
    } catch {
      setFormError('Unable to save staff profile. Verify the badge ID and email are unique, and passwords are at least 14 characters.')
    } finally {
      setSaving(false)
    }
  }

  async function changeStatus(member: StaffMember, status: StaffStatus) {
    setError('')
    try {
      await api.patch(`/staff/${member._id}`, { status })
      setStaff((current) => current.map((item) => item._id === member._id ? { ...item, status } : item))
      onNotify(`${member.fullName} is now ${status.toLowerCase().replaceAll('_', ' ')}.`)
    } catch {
      setError('Unable to update staff status.')
    }
  }

  async function confirmDelete() {
    if (!deleting) return
    setError('')
    try {
      await api.delete(`/staff/${deleting._id}`)
      setStaff((current) => current.filter((member) => member._id !== deleting._id))
      onNotify('Staff account deleted.')
      setDeleting(null)
    } catch {
      setError('Unable to delete this staff account. Your active administrator account cannot be deleted.')
    }
  }

  return <div className="staff-page">
    <section className="panel full-panel staff-directory">
      <div className="panel-header">
        <div><div className="panel-title">Staff directory <span className="small-count">{staff.length}</span></div><div className="panel-subtitle">Manage cybersecurity staff, account status, and access tiers.</div></div>
        <button className="button-primary" onClick={openCreate}><CirclePlus size={15} />Add staff member</button>
      </div>
      <div className="staff-toolbar">
        <div className="input-wrap"><Search size={15} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search name, email, or badge ID..." /></div>
        <select className="select-button native-select" value={roleFilter} onChange={(event) => setRoleFilter(event.target.value)}><option value="ALL">All roles</option>{roles.map((role) => <option key={role} value={role}>{roleTitles[role]}</option>)}</select>
        <select className="select-button native-select" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option value="ALL">All statuses</option><option value="ACTIVE">Active</option><option value="SUSPENDED">Suspended</option><option value="ON_LEAVE">On leave</option></select>
      </div>
      {error && <div className="staff-error" role="alert">{error}</div>}
      <div className="table-scroll"><table className="data-table staff-table"><thead><tr><th>BADGE ID</th><th>FULL NAME</th><th>EMAIL</th><th>DEPARTMENT</th><th>ROLE</th><th>STATUS</th><th>LAST LOGIN</th><th /></tr></thead>
        <tbody>{visibleStaff.map((member) => <tr key={member._id}>
          <td className="mono-cell">{member.badgeId}</td>
          <td><strong className="staff-name">{member.fullName}</strong></td>
          <td>{member.email}</td>
          <td>{member.department}</td>
          <td><span className={`staff-role-badge ${roleClass[member.role]}`}>{roleTitles[member.role]}</span></td>
          <td><select className={`staff-status-select status-${member.status.toLowerCase()}`} aria-label={`Status for ${member.fullName}`} value={member.status} onChange={(event) => void changeStatus(member, event.target.value as StaffStatus)}><option value="ACTIVE">Active</option><option value="SUSPENDED">Suspended</option><option value="ON_LEAVE">On leave</option></select></td>
          <td className="mono-cell">{member.lastLogin ? new Date(member.lastLogin).toLocaleString() : 'Never'}</td>
          <td><div className="staff-row-actions"><button className="icon-button" aria-label={`Edit ${member.fullName}`} onClick={() => openEdit(member)}><Pencil size={15} /></button><button className="icon-button danger-action" aria-label={`Delete ${member.fullName}`} onClick={() => setDeleting(member)}><Trash2 size={15} /></button></div></td>
        </tr>)}</tbody>
      </table>
      {!loading && !visibleStaff.length && <div className="empty-state">No staff members match these filters.</div>}
      {loading && <div className="empty-state">Loading staff directory...</div>}</div>
      <div className="table-footer"><span>Showing {visibleStaff.length} of {staff.length} staff members</span><span><LockKeyhole size={13} /> Staff access is administrator-only</span></div>
    </section>

    <section className="panel permission-matrix"><div className="panel-header"><div><div className="panel-title"><ShieldCheck size={17} />Role permission matrix</div><div className="panel-subtitle">Reference for the capabilities granted to each clearance tier.</div></div><Users size={17} className="muted-icon" /></div>
      <div className="permission-matrix-list">{permissionRows.map(({ role, permissions }) => <div className="permission-matrix-row" key={role}><span className={`staff-role-badge ${roleClass[role]}`}>{roleTitles[role]}</span><span>{permissions}</span></div>)}</div>
    </section>

    {formOpen && <StaffForm member={editing} saving={saving} error={formError} onClose={() => setFormOpen(false)} onSubmit={saveStaff} />}
    {deleting && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setDeleting(null) }}><section className="login-modal confirm-delete"><div className="modal-header"><div><span className="eyebrow">REVOKE ACCESS</span><h2>Delete staff account?</h2></div><button className="icon-button" onClick={() => setDeleting(null)} aria-label="Close delete confirmation"><X size={18} /></button></div><p className="modal-description">This permanently removes <strong>{deleting.fullName}</strong> ({deleting.badgeId}) and revokes their access. This action cannot be undone.</p><div className="modal-actions"><button className="button-secondary" onClick={() => setDeleting(null)}>Cancel</button><button className="button-danger" onClick={() => void confirmDelete()}><Trash2 size={14} />Delete account</button></div></section></div>}
  </div>
}

function StaffForm({ member, saving, error, onClose, onSubmit }: { member: StaffMember | null; saving: boolean; error: string; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void }) {
  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><section className="login-modal staff-form-modal">
    <div className="modal-header"><div><span className="eyebrow">STAFF &amp; RBAC</span><h2>{member ? 'Edit staff member' : 'Add staff member'}</h2></div><button className="icon-button" onClick={onClose} aria-label="Close staff form"><X size={18} /></button></div>
    <form onSubmit={onSubmit}>{error && <div className="staff-error" role="alert">{error}</div>}<div className="staff-form-grid">
      <label>Full name<input name="fullName" required minLength={2} maxLength={120} defaultValue={member?.fullName ?? ''} /></label>
      <label>Email address<input name="email" type="email" required maxLength={254} defaultValue={member?.email ?? ''} /></label>
      <label>Badge ID<input name="badgeId" required minLength={3} maxLength={32} defaultValue={member?.badgeId ?? ''} placeholder="SOC-1042" /></label>
      <label>Department<select name="department" defaultValue={member?.department ?? emptyForm.department}>{departments.map((department) => <option key={department}>{department}</option>)}</select></label>
      <label>Role<select name="role" defaultValue={member?.role ?? emptyForm.role}>{roles.map((role) => <option key={role} value={role}>{roleTitles[role]}</option>)}</select></label>
      <label>Account status<select name="status" defaultValue={member?.status ?? emptyForm.status}><option value="ACTIVE">Active</option><option value="SUSPENDED">Suspended</option><option value="ON_LEAVE">On leave</option></select></label>
      <label className="staff-password-field">{member ? 'New password (optional)' : 'Initial password'}<input name="password" type="password" autoComplete="new-password" minLength={14} maxLength={200} required={!member} placeholder="At least 14 characters" /></label>
    </div><div className="modal-actions"><button type="button" className="button-secondary" onClick={onClose}>Cancel</button><button type="submit" className="button-primary" disabled={saving}>{saving ? 'Saving...' : member ? 'Save changes' : 'Create account'}</button></div></form>
  </section></div>
}
