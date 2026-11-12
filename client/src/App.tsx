import { useEffect, useMemo, useState, type FormEvent } from 'react'
import {
  Activity, ArrowDownRight, ArrowUpRight, Bell, Blocks, BookOpenCheck,
  ChevronDown, CircleHelp, Crosshair, Database, Download, FileSearch,
  Filter, Globe2, LayoutDashboard, LockKeyhole, Menu, MoreHorizontal,
  Network, Search, Settings2, Shield, ShieldAlert, ShieldCheck, Siren, Terminal,
  Timer, Users, X,
} from 'lucide-react'
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { api } from './services/api'
import { useAuth } from './context/AuthContext'
import { useSocket } from './context/SocketContext'
import { SeverityBadge } from './components/SeverityBadge'
import { PageHeader } from './pages/PageHeader'
import { StaffManagement } from './pages/StaffManagement'
import './login.css'
import './dashboard-enhancements.css'
import type { Incident, LogEntry, NetworkZone, Role, Severity } from './types'

type View = 'Overview' | 'Incidents' | 'Threat hunting' | 'Event stream' | 'Access control' | 'Staff & RBAC'
const navigation: { name: View; icon: typeof LayoutDashboard }[] = [
  { name: 'Overview', icon: LayoutDashboard },
  { name: 'Incidents', icon: Siren },
  { name: 'Threat hunting', icon: Crosshair },
  { name: 'Event stream', icon: Terminal },
  { name: 'Access control', icon: Users },
  { name: 'Staff & RBAC', icon: Users },
]

const seededIncidents: Incident[] = [
  { _id: 'INC-2481', title: 'Unusual outbound data transfer', description: 'Sustained encrypted transfer from a finance workstation to an unclassified external host.', severity: 'CRITICAL', status: 'OPEN', affectedHosts: ['FIN-WS-042', '10.24.8.42'], mitreAttackTechnique: 'T1041 · Exfiltration Over C2 Channel', createdAt: new Date(Date.now() - 8 * 60000).toISOString(), networkZone: 'INTRANET', targetNode: { hostname: 'FIN-WS-042', ipAddress: '10.24.8.42', nodeType: 'WORKSTATION', os: 'Windows 11', isIsolated: false }, escalationRole: 'SOC_ANALYST_L1', escalationHistory: [] },
  { _id: 'INC-2479', title: 'Repeated authentication failures', description: 'High-volume credential failures across privileged accounts.', severity: 'HIGH', status: 'CONTAINED', affectedHosts: ['IDP-CORE-01'], mitreAttackTechnique: 'T1110 · Brute Force', createdAt: new Date(Date.now() - 42 * 60000).toISOString(), networkZone: 'INTRANET', targetNode: { hostname: 'IDP-CORE-01', ipAddress: '10.24.0.12', nodeType: 'DOMAIN_CONTROLLER', os: 'Windows Server 2022', isIsolated: false }, escalationRole: 'SOC_ANALYST_L1', escalationHistory: [] },
  { _id: 'INC-2475', title: 'Endpoint malware detection', description: 'Suspicious executable quarantined by endpoint protection.', severity: 'MEDIUM', status: 'OPEN', affectedHosts: ['ENG-LT-118'], mitreAttackTechnique: 'T1204 · User Execution', createdAt: new Date(Date.now() - 110 * 60000).toISOString(), networkZone: 'REMOTE_ENDPOINT', targetNode: { hostname: 'ENG-LT-118', ipAddress: '10.42.7.18', nodeType: 'WORKSTATION', os: 'Windows 11', isIsolated: false }, escalationRole: 'SOC_ANALYST_L1', escalationHistory: [] },
  { _id: 'INC-2471', title: 'DNS beaconing pattern', description: 'Periodic low-volume DNS requests to a newly registered domain.', severity: 'LOW', status: 'RESOLVED', affectedHosts: ['DEV-VM-207'], mitreAttackTechnique: 'T1071.004 · DNS', createdAt: new Date(Date.now() - 260 * 60000).toISOString(), networkZone: 'DMZ', targetNode: { hostname: 'DEV-VM-207', ipAddress: '10.32.7.20', nodeType: 'WORKSTATION', os: 'Ubuntu 24.04', isIsolated: false }, escalationRole: 'SOC_ANALYST_L1', escalationHistory: [], resolutionNote: 'Known approved resolver pattern confirmed.', resolvedAt: new Date(Date.now() - 245 * 60000).toISOString() },
]

const seedLogs: LogEntry[] = [
  { _id: 'evt-01', timestamp: new Date(Date.now() - 20000).toISOString(), sourceIp: '10.24.8.42', destIp: '185.199.110.153', protocol: 'HTTPS', severity: 'CRITICAL', eventCategory: 'DATA_EXFILTRATION', rawPayload: 'TLS session volume exceeded baseline by 840% · 1.8 GB transferred', status: 'INVESTIGATING', networkZone: 'INTRANET', targetNode: { hostname: 'FIN-WS-042', ipAddress: '10.24.8.42', nodeType: 'WORKSTATION', os: 'Windows 11', isIsolated: false }, mitreAttackTechnique: 'T1041 · Exfiltration Over C2 Channel' },
  { _id: 'evt-02', timestamp: new Date(Date.now() - 47000).toISOString(), sourceIp: '10.24.3.18', destIp: '10.24.0.12', protocol: 'TCP', severity: 'HIGH', eventCategory: 'AUTH_FAILURE', rawPayload: 'Repeated failed login for svc_backup · 38 attempts / 60 sec', status: 'UNRESOLVED', networkZone: 'INTRANET', targetNode: { hostname: 'IDP-CORE-01', ipAddress: '10.24.0.12', nodeType: 'DOMAIN_CONTROLLER', os: 'Windows Server 2022', isIsolated: false }, mitreAttackTechnique: 'T1110 · Brute Force' },
  { _id: 'evt-03', timestamp: new Date(Date.now() - 78000).toISOString(), sourceIp: '10.24.12.6', destIp: '45.83.64.21', protocol: 'DNS', severity: 'HIGH', eventCategory: 'IOC_MATCH', rawPayload: 'Domain matched known C2 indicator · confidence 96%', status: 'INVESTIGATING', networkZone: 'EXTRANET', targetNode: { hostname: 'EXT-GW-01', ipAddress: '203.0.113.18', nodeType: 'WEB_GATEWAY', os: 'Linux', isIsolated: false }, mitreAttackTechnique: 'T1071.004 · DNS' },
  { _id: 'evt-04', timestamp: new Date(Date.now() - 130000).toISOString(), sourceIp: '10.24.5.92', destIp: '10.24.5.1', protocol: 'UDP', severity: 'MEDIUM', eventCategory: 'PORT_SCAN', rawPayload: 'Sequential port sweep detected · 41 ports in 12 sec', status: 'UNRESOLVED', networkZone: 'DMZ', targetNode: { hostname: 'DMZ-SENSOR-01', ipAddress: '10.24.5.1', nodeType: 'IOT_SENSOR', os: 'Embedded Linux', isIsolated: false }, mitreAttackTechnique: 'T1046 · Network Service Discovery' },
  { _id: 'evt-05', timestamp: new Date(Date.now() - 195000).toISOString(), sourceIp: '10.24.14.77', destIp: '10.24.0.20', protocol: 'TCP', severity: 'LOW', eventCategory: 'POLICY_CHANGE', rawPayload: 'Local firewall rule modified by approved deployment', status: 'MITIGATED', networkZone: 'CLOUD_VPC', targetNode: { hostname: 'CLOUD-DB-01', ipAddress: '10.24.0.20', nodeType: 'DATABASE_SERVER', os: 'Ubuntu 24.04', isIsolated: false }, mitreAttackTechnique: 'T1562 · Impair Defenses' },
]

const chartData = [
  { time: '09:00', events: 24, threats: 3 }, { time: '09:10', events: 38, threats: 5 },
  { time: '09:20', events: 31, threats: 4 }, { time: '09:30', events: 52, threats: 8 },
  { time: '09:40', events: 44, threats: 6 }, { time: '09:50', events: 68, threats: 11 },
  { time: '10:00', events: 54, threats: 8 }, { time: '10:10', events: 82, threats: 14 },
  { time: '10:20', events: 72, threats: 12 }, { time: '10:30', events: 96, threats: 18 },
]

const severityClass: Record<Severity, string> = {
  LOW: 'severity-low', MEDIUM: 'severity-medium', HIGH: 'severity-high', CRITICAL: 'severity-critical',
}

function canViewIncident(role: Role, incident: Incident) {
  return role === 'ADMIN' || role === 'INCIDENT_COMMANDER' || (incident.escalationRole ?? 'SOC_ANALYST_L1') === role
}

function App() {
  const [view, setView] = useState<View>('Overview')
  const [incidents, setIncidents] = useState<Incident[]>(seededIncidents)
  const [logs, setLogs] = useState(seedLogs)
  const [role, setRole] = useState<Role>('SOC_ANALYST_L1')
  const [query, setQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [zoneFilter, setZoneFilter] = useState<NetworkZone | 'ALL'>('ALL')
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null)
  const [toast, setToast] = useState('')
  const [streaming, setStreaming] = useState(true)
  const [demoMode, setDemoMode] = useState(true)
  const [mobileNav, setMobileNav] = useState(false)
  const [loginOpen, setLoginOpen] = useState(false)
  const [simulationNextRunAt, setSimulationNextRunAt] = useState<string | null>(null)
  const [countdownNow, setCountdownNow] = useState(Date.now())
  const [triggeringBatch, setTriggeringBatch] = useState(false)
  const { token, user, login, logout } = useAuth()
  const { socket, connected: live } = useSocket()

  useEffect(() => {
    if (token) {
      api.get('/incidents').then(({ data }) => {
        if (Array.isArray(data.data)) { setIncidents(data.data); setDemoMode(false) }
      }).catch(() => undefined)
      api.get('/logs?limit=30').then(({ data }) => {
        if (Array.isArray(data.data)) setLogs(data.data)
      }).catch(() => undefined)
      api.get('/simulation/status').then(({ data }) => setSimulationNextRunAt(data.data.nextRunAt)).catch(() => setSimulationNextRunAt(null))
    }
    socket.on('log:new', (entry: LogEntry) => setLogs((current) => [entry, ...current.filter((item) => item._id !== entry._id)].slice(0, 30)))
    socket.on('threat:new_batch', (batch: { logs: LogEntry[]; incidents: Incident[] }) => {
      setLogs((current) => [...batch.logs, ...current.filter((item) => !batch.logs.some((entry) => entry._id === item._id))].slice(0, 30))
      setIncidents((current) => [...batch.incidents, ...current.filter((item) => !batch.incidents.some((incident) => incident._id === item._id))].slice(0, 200))
      notify(`${batch.logs.length} simulated threats received`)
    })
    socket.on('incident:updated', (incident: Incident | { _id: string; escalationRole: Role; accessRevoked: true }) => {
      if ('accessRevoked' in incident) {
        const incidentId = incident._id
        setIncidents((current) => current.filter((item) => item._id !== incidentId))
        setSelectedIncident((current) => current?._id === incidentId ? null : current)
        return
      }
      setIncidents((current) => current.some((item) => item._id === incident._id)
        ? current.map((item) => item._id === incident._id ? incident : item)
        : [incident, ...current].slice(0, 200))
      setSelectedIncident((current) => current?._id === incident._id ? incident : current)
    })
    socket.on('alert:critical', (alert: { message?: string }) => notify(alert.message ?? 'Critical indicator match detected'))
    return () => { socket.off('log:new'); socket.off('threat:new_batch'); socket.off('incident:updated'); socket.off('alert:critical') }
  }, [socket, token])

  useEffect(() => {
    if (user) setRole(user.role)
    if (!user && view === 'Staff & RBAC') setView('Overview')
  }, [user, view])

  useEffect(() => {
    if (selectedIncident && !canViewIncident(role, selectedIncident)) setSelectedIncident(null)
  }, [role, selectedIncident])

  useEffect(() => {
    const timer = window.setInterval(() => setCountdownNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    if (live || !streaming) return
    const timer = window.setInterval(() => {
      const source = `10.24.${Math.floor(Math.random() * 20)}.${Math.floor(Math.random() * 240 + 10)}`
      const severity: Severity = Math.random() > 0.88 ? 'HIGH' : Math.random() > 0.63 ? 'MEDIUM' : 'LOW'
      const event: LogEntry = {
        _id: `demo-${Date.now()}`, timestamp: new Date().toISOString(), sourceIp: source,
        destIp: `10.24.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 240 + 10)}`,
        protocol: ['HTTPS', 'TCP', 'DNS', 'UDP'][Math.floor(Math.random() * 4)], severity,
        eventCategory: ['AUTH_FAILURE', 'POLICY_CHANGE', 'DNS_QUERY', 'PORT_SCAN'][Math.floor(Math.random() * 4)],
        rawPayload: 'Telemetry received from monitored network segment', status: 'UNRESOLVED',
        networkZone: (['INTRANET', 'EXTRANET', 'DMZ', 'REMOTE_ENDPOINT'] as const)[Math.floor(Math.random() * 4)],
        targetNode: { hostname: `DEMO-WS-${String(Math.floor(Math.random() * 100)).padStart(3, '0')}`, ipAddress: source, nodeType: 'WORKSTATION', os: 'Windows 11', isIsolated: false },
        mitreAttackTechnique: 'T1071 · Application Layer Protocol',
      }
      setLogs((current) => [event, ...current].slice(0, 30))
    }, 4200)
    return () => window.clearInterval(timer)
  }, [live, streaming])

  function notify(message: string) {
    setToast(message)
    window.setTimeout(() => setToast(''), 3500)
  }

  async function containIncident(incident: Incident) {
    if (role !== 'ADMIN' && role !== 'INCIDENT_COMMANDER' && role !== 'THREAT_HUNTER_L2') {
      notify('Access denied · host isolation requires L2 or Incident Commander clearance')
      return
    }
    try {
      await api.post('/containment/isolate', { host: incident.affectedHosts[0], incidentId: incident._id })
      setDemoMode(false)
    } catch {
      if (token) {
        notify('Unable to record containment. Verify your clearance and API connection.')
        return
      }
    }
    setIncidents((current) => current.map((item) => item._id === incident._id ? { ...item, status: 'CONTAINED' } : item))
    setSelectedIncident(null)
    notify(`Simulated containment recorded for ${incident.affectedHosts[0]}`)
  }

  async function blockIndicator(incident: Incident) {
    if (role !== 'ADMIN' && role !== 'INCIDENT_COMMANDER' && role !== 'THREAT_HUNTER_L2') {
      notify('Access denied · indicator blocking requires L2 or Incident Commander clearance')
      return
    }
    const indicator = '45.83.64.21'
    try {
      await api.post('/containment/blacklist', { indicator, incidentId: incident._id })
      setDemoMode(false)
    } catch {
      if (token) {
        notify('Unable to record the indicator block. Verify your clearance and API connection.')
        return
      }
    }
    notify(`Simulated network block recorded for ${indicator}`)
  }

  async function triggerThreatBatch() {
    if (!user || user.role !== 'ADMIN') return
    setTriggeringBatch(true)
    try {
      const { data } = await api.post<{ data: { logs: LogEntry[]; incidents: Incident[] } }>('/simulation/trigger-now')
      setLogs((current) => [...data.data.logs, ...current.filter((item) => !data.data.logs.some((entry) => entry._id === item._id))].slice(0, 30))
      setIncidents((current) => [...data.data.incidents, ...current.filter((item) => !data.data.incidents.some((incident) => incident._id === item._id))].slice(0, 200))
      setDemoMode(false)
      notify('Five simulated threats generated.')
    } catch {
      notify('Unable to trigger threat simulation. Check your admin session and API connection.')
    } finally {
      setTriggeringBatch(false)
    }
  }

  async function escalateIncident(incident: Incident, note: string): Promise<boolean> {
    if (token) {
      try {
        const { data } = await api.post<{ data: Incident }>(`/incidents/${incident._id}/escalate`, { note })
        updateIncident(data.data)
        notify(`Incident escalated to ${data.data.escalationRole.replaceAll('_', ' ')}.`)
        return true
      } catch {
        notify('Unable to escalate incident. It may already be at the highest tier or have been updated elsewhere.')
        return false
      }
    }

    const hierarchy = ['SOC_ANALYST_L1', 'THREAT_HUNTER_L2', 'INCIDENT_COMMANDER', 'CISO'] as const
    const escalationRole = incident.escalationRole ?? 'SOC_ANALYST_L1'
    const nextRole = hierarchy[hierarchy.indexOf(escalationRole) + 1]
    if (!nextRole) {
      notify('Incident is already at the highest escalation tier (CISO).')
      return false
    }
    updateIncident({
      ...incident,
      escalationRole: nextRole,
      escalationHistory: [...(incident.escalationHistory ?? []), {
        fromRole: escalationRole,
        toRole: nextRole,
        note,
        author: user?.email ?? 'Demo analyst',
        timestamp: new Date().toISOString(),
      }],
    })
    notify(`Demo incident escalated to ${nextRole.replaceAll('_', ' ')}.`)
    return true
  }

  async function resolveIncident(incident: Incident, note: string): Promise<boolean> {
    if (token) {
      try {
        const { data } = await api.post<{ data: Incident }>(`/incidents/${incident._id}/resolve`, { note })
        updateIncident(data.data)
        notify('Incident resolved and resolution notes saved.')
        return true
      } catch {
        notify('Unable to resolve incident. It may already be closed or have been updated elsewhere.')
        return false
      }
    }
    const resolvedAt = new Date().toISOString()
    updateIncident({ ...incident, status: 'RESOLVED', resolutionNote: note, resolvedAt })
    notify('Demo incident resolved and notes saved.')
    return true
  }

  function updateIncident(incident: Incident) {
    setIncidents((current) => current.map((item) => item._id === incident._id ? incident : item))
    setSelectedIncident(incident)
  }

  const filteredLogs = useMemo(() => logs.filter((log) => {
    const matchesText = `${log.sourceIp} ${log.destIp} ${log.eventCategory} ${log.rawPayload} ${log.targetNode.hostname}`.toLowerCase().includes(query.toLowerCase())
    return matchesText && (severityFilter === 'ALL' || log.severity === severityFilter) && (zoneFilter === 'ALL' || log.networkZone === zoneFilter)
  }), [logs, query, severityFilter, zoneFilter])
  const visibleIncidents = useMemo(
    () => incidents.filter((incident) => canViewIncident(role, incident)),
    [incidents, role],
  )

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}>
        <div className="brand"><div className="brand-mark"><Shield size={19} strokeWidth={2.2} /></div><div><strong>CYBERSHIELD</strong><span>SECURITY OPERATIONS</span></div><button className="mobile-close icon-button" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X size={17} /></button></div>
        <div className="workspace-switch"><div className="workspace-avatar">N</div><div><strong>Northstar Group</strong><span>Production environment</span></div><ChevronDown size={14} /></div>
        <div className="nav-label">WORKSPACE</div>
        <nav className="nav-list" aria-label="Main navigation">{navigation.filter(({ name }) => name !== 'Staff & RBAC' || user?.role === 'ADMIN').map(({ name, icon: Icon }) => <button key={name} onClick={() => { setView(name); setMobileNav(false) }} className={`nav-item ${view === name ? 'active' : ''}`}><Icon size={17} /><span>{name}</span>{name === 'Incidents' && <span className="nav-count">{visibleIncidents.filter((item) => item.status === 'OPEN').length}</span>}</button>)}</nav>
        <div className="sidebar-bottom"><div className="sensor-card"><div className="sensor-title"><span className="live-dot" />SENSOR NETWORK <span>HEALTHY</span></div><div className="sensor-metrics"><strong>18 / 18</strong><small>collectors online</small></div><div className="sensor-bars">{Array.from({ length: 22 }, (_, index) => <i key={index} style={{ height: `${18 + ((index * 19) % 46)}%` }} />)}</div></div><button className="nav-item"><Settings2 size={17} /><span>Workspace settings</span></button><div className="profile"><div className="profile-avatar">{(user?.name ?? 'Guest User').split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase()}</div><div className="profile-copy"><strong>{user?.name ?? 'Demo analyst'}</strong><span>{role.replaceAll('_', ' ')}</span></div><MoreHorizontal size={18} /></div></div>
      </aside>
      {mobileNav && <button className="nav-backdrop" onClick={() => setMobileNav(false)} aria-label="Close navigation" />}

      <main className="main-area">
        <header className="topbar"><div className="topbar-left"><button className="mobile-menu icon-button" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={19} /></button><div className="breadcrumbs">Operations <span>/</span> <strong>{view}</strong></div></div><div className="topbar-right"><div className={`connection ${live ? 'connected' : ''}`}><span className="live-dot" />{live ? 'LIVE CONNECTION' : 'DEMO STREAM'}</div><div className="simulation-status"><span className="live-dot" />Next escalation <strong>{simulationNextRunAt ? formatCountdown(simulationNextRunAt, countdownNow) : 'Unavailable'}</strong></div>{user?.role === 'ADMIN' && <button className="button-primary simulate-now" onClick={() => void triggerThreatBatch()} disabled={triggeringBatch}><Activity size={14} />{triggeringBatch ? 'Generating...' : 'Simulate +5 Threats Now'}</button>}<button className="icon-button top-icon" aria-label="Search" onClick={() => document.getElementById('global-search')?.focus()}><Search size={17} /></button><button className="icon-button top-icon notification-button" aria-label="Notifications"><Bell size={17} /><i /></button><button className="auth-button" onClick={() => token ? logout() : setLoginOpen(true)}>{token ? 'Sign out' : 'Connect API'}</button><div className="top-divider" /><span className="current-time">{new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short' })}</span></div></header>
        <div className="page-content">
          <PageHeader title={view === 'Overview' ? 'Command center' : view} subtitle={view === 'Overview' ? 'Threat activity across your environment, at a glance.' : pageSubtitle(view)} actions={<><button className="button-secondary" onClick={() => notify('Report export is available when connected to the API')}><Download size={15} />Export report</button><button className="button-primary" onClick={() => setView('Incidents')}><ShieldAlert size={15} />Review incidents</button></>} />
          {view === 'Overview' && <Overview incidents={visibleIncidents} logs={logs} zoneFilter={zoneFilter} setZoneFilter={setZoneFilter} streaming={streaming} setStreaming={setStreaming} onSelect={setSelectedIncident} onContain={containIncident} onBlock={blockIndicator} role={role} />}
          {view === 'Incidents' && <Incidents incidents={visibleIncidents} onSelect={setSelectedIncident} onContain={containIncident} />}
          {view === 'Threat hunting' && <Hunting logs={logs} zoneFilter={zoneFilter} setZoneFilter={setZoneFilter} />}
          {view === 'Event stream' && <EventStream logs={filteredLogs} query={query} setQuery={setQuery} severity={severityFilter} setSeverity={setSeverityFilter} streaming={streaming} setStreaming={setStreaming} />}
          {view === 'Access control' && <AccessControl role={role} setRole={setRole} notify={notify} allowPreview={!token} />}
          {view === 'Staff & RBAC' && user?.role === 'ADMIN' && <StaffManagement onNotify={notify} />}
          <footer className="footer"><span><span className="live-dot" /> All systems operational</span><span>CYBERSHIELD SOC <b>·</b> v1.0.0 <b>·</b> {demoMode ? 'DEMO DATA' : 'CONNECTED TO API'}</span></footer>
        </div>
      </main>
      {selectedIncident && <IncidentModal incident={selectedIncident} onClose={() => setSelectedIncident(null)} onContain={containIncident} onEscalate={escalateIncident} onResolve={resolveIncident} role={role} />}
      {loginOpen && <LoginModal onClose={() => setLoginOpen(false)} onLogin={login} />}
      {toast && <div className="toast"><ShieldCheck size={17} />{toast}</div>}
    </div>
  )
}

function pageSubtitle(view: View) {
  return ({ Incidents: 'Triage active cases and coordinate response.', 'Threat hunting': 'Explore patterns across telemetry and indicators.', 'Event stream': 'Filter and investigate live security events.', 'Access control': 'Review analyst permissions and clearance boundaries.', 'Staff & RBAC': 'Manage SOC staff, account status, and role permissions.', Overview: '' })[view]
}

function Metric({ label, value, note, trend, icon: Icon, tone }: { label: string; value: string; note: string; trend?: string; icon: typeof Activity; tone: string }) {
  return <div className="metric"><div className="metric-top"><span>{label}</span><div className={`metric-icon ${tone}`}><Icon size={16} /></div></div><div className="metric-value">{value}</div><div className="metric-bottom"><span className="metric-note">{trend && <b className={trend.startsWith('+') ? 'trend-up' : 'trend-down'}>{trend.startsWith('+') ? <ArrowUpRight size={13} /> : <ArrowDownRight size={13} />}{trend}</b>}{note}</span><span className="metric-period">vs last hour</span></div></div>
}

function Overview({ incidents, logs, zoneFilter, setZoneFilter, streaming, setStreaming, onSelect, onContain, onBlock, role }: { incidents: Incident[]; logs: LogEntry[]; zoneFilter: NetworkZone | 'ALL'; setZoneFilter: (zone: NetworkZone | 'ALL') => void; streaming: boolean; setStreaming: (value: boolean) => void; onSelect: (incident: Incident) => void; onContain: (incident: Incident) => void; onBlock: (incident: Incident) => void; role: Role }) {
  const openCount = incidents.filter((incident) => incident.status === 'OPEN').length
  const visibleLogs = logs.filter((log) => zoneFilter === 'ALL' || log.networkZone === zoneFilter)
  return <>
    <div className="metric-grid"><Metric label="OPEN INCIDENTS" value={String(openCount).padStart(2, '0')} note="3 require attention" trend="+2" icon={Siren} tone="metric-red" /><Metric label="EVENTS / SECOND" value="1,284" note="telemetry throughput" trend="+12%" icon={Activity} tone="metric-green" /><Metric label="MEAN TIME TO DETECT" value="04:32" note="below 5m target" trend="−18%" icon={Timer} tone="metric-blue" /><Metric label="THREAT INDICATORS" value="247" note="12 matched today" trend="+4" icon={Crosshair} tone="metric-amber" /></div>
    <div className="zone-toolbar"><ZoneFilterBar selected={zoneFilter} onChange={setZoneFilter} /><ZoneDistribution logs={logs} /></div>
    <div className="overview-grid"><section className="panel activity-panel"><div className="panel-header"><div><div className="panel-title">Threat activity</div><div className="panel-subtitle">Events and high-confidence detections · last 90 minutes</div></div><button className="select-button">Last 90 minutes <ChevronDown size={14} /></button></div><div className="chart-legend"><span><i className="legend-event" />Events ingested</span><span><i className="legend-threat" />Threat detections</span></div><div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chartData} margin={{ top: 8, right: 4, left: -20, bottom: 0 }}><defs><linearGradient id="eventFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#b7f36b" stopOpacity={0.18} /><stop offset="100%" stopColor="#b7f36b" stopOpacity={0} /></linearGradient><linearGradient id="threatFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#ff745f" stopOpacity={0.18} /><stop offset="100%" stopColor="#ff745f" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#2a383d" vertical={false} /><XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fill: '#77878a', fontSize: 10, fontFamily: 'DM Mono' }} dy={10} /><YAxis tickLine={false} axisLine={false} tick={{ fill: '#77878a', fontSize: 10, fontFamily: 'DM Mono' }} /><Tooltip contentStyle={{ background: '#172125', border: '1px solid #35464a', borderRadius: 4, fontSize: 11 }} /><Area type="monotone" dataKey="events" stroke="#b7f36b" strokeWidth={2} fill="url(#eventFill)" /><Area type="monotone" dataKey="threats" stroke="#ff745f" strokeWidth={2} fill="url(#threatFill)" /></AreaChart></ResponsiveContainer></div><div className="chart-foot"><span><span className="live-dot" /> STREAMING DATA</span><span>PEAK: 1,482 EVENTS / SEC</span></div></section>
      <section className="panel priority-panel"><div className="panel-header"><div><div className="panel-title">Priority queue <span className="small-count">{openCount}</span></div><div className="panel-subtitle">Incidents needing analyst review</div></div><button className="text-action" onClick={() => onSelect(incidents[0])}>View all <ArrowUpRight size={14} /></button></div><div className="priority-list">{incidents.filter((incident) => incident.status === 'OPEN').slice(0, 3).map((incident) => <button className="priority-item" key={incident._id} onClick={() => onSelect(incident)}><span className={`priority-mark ${severityClass[incident.severity]}`} /><span className="priority-copy"><strong>{incident.title}</strong><small>{incident._id} <i>·</i> {incident.affectedHosts[0]}</small></span><span className={`severity-tag ${severityClass[incident.severity]}`}>{incident.severity}</span></button>)}</div><div className="priority-bottom"><ShieldCheck size={15} /><span>Response posture</span><strong>Contained</strong></div></section>
    </div>
    <section className="panel live-panel"><div className="panel-header"><div><div className="panel-title live-title"><span className="live-dot" />Live event stream</div><div className="panel-subtitle">Security telemetry from your monitored network</div></div><div className="stream-actions"><button className="button-quiet" onClick={() => setStreaming(!streaming)}>{streaming ? 'Pause stream' : 'Resume stream'} <span className={streaming ? 'pause-symbol' : 'play-symbol'}>{streaming ? 'Ⅱ' : '▶'}</span></button><button className="icon-button" aria-label="Open event stream"><MoreHorizontal size={18} /></button></div></div><div className="table-scroll"><table className="data-table"><thead><tr><th>TIME</th><th>SEVERITY</th><th>EVENT</th><th>SOURCE → DESTINATION</th><th>NETWORK NODE / ZONE</th><th>PROTOCOL</th><th>STATUS</th></tr></thead><tbody>{visibleLogs.slice(0, 5).map((log) => <LogRow key={log._id} log={log} />)}</tbody></table>{!visibleLogs.length && <div className="empty-state">No events in this network zone.</div>}</div><div className="table-footer"><span>Showing latest {Math.min(5, visibleLogs.length)} events</span><span>Updated just now <span className="live-dot" /></span></div></section>
    <div className="lower-grid"><section className="panel lower-panel"><div className="panel-header"><div><div className="panel-title">Response actions</div><div className="panel-subtitle">Permission-gated · actions are simulated in this environment</div></div><LockKeyhole size={15} className="muted-icon" /></div><div className="response-actions"><button className="response-action" onClick={() => onContain(incidents.find((item) => item.status === 'OPEN') ?? incidents[0])}><span className="action-icon action-red"><Blocks size={17} /></span><span><strong>Isolate host</strong><small>Endpoint containment</small></span><ArrowUpRight size={14} /></button><button className="response-action" onClick={() => onBlock(incidents.find((item) => item.status === 'OPEN') ?? incidents[0])}><span className="action-icon action-amber"><Globe2 size={17} /></span><span><strong>Block indicator</strong><small>Network policy action</small></span><ArrowUpRight size={14} /></button></div><div className="action-permission"><LockKeyhole size={13} /> Current clearance: <b>{role.replaceAll('_', ' ')}</b></div></section><section className="panel lower-panel"><div className="panel-header"><div><div className="panel-title">MITRE ATT&amp;CK coverage</div><div className="panel-subtitle">Observed tactics · last 24 hours</div></div><button className="icon-button" aria-label="More coverage details"><MoreHorizontal size={18} /></button></div><div className="mitre-row"><div className="mitre-card"><span>TA0001</span><strong>Initial access</strong><i style={{ width: '74%' }} /></div><div className="mitre-card"><span>TA0005</span><strong>Defense evasion</strong><i style={{ width: '48%' }} /></div><div className="mitre-card"><span>TA0010</span><strong>Exfiltration</strong><i style={{ width: '88%' }} /></div></div><div className="mitre-footer"><span><span className="coverage-dot" /> 14 techniques observed</span><span>View matrix <ArrowUpRight size={13} /></span></div></section></div>
  </>
}

function ZoneFilterBar({ selected, onChange }: { selected: NetworkZone | 'ALL'; onChange: (zone: NetworkZone | 'ALL') => void }) {
  const zones: (NetworkZone | 'ALL')[] = ['ALL', 'INTRANET', 'EXTRANET', 'DMZ', 'REMOTE_ENDPOINT']
  return <div className="zone-filter" aria-label="Filter by network zone">{zones.map((zone) => <button key={zone} className={selected === zone ? 'zone-filter-active' : ''} onClick={() => onChange(zone)}>{zone === 'ALL' ? 'ALL' : zone.replaceAll('_', ' ')}</button>)}</div>
}

function ZoneDistribution({ logs }: { logs: LogEntry[] }) {
  const zones: NetworkZone[] = ['INTRANET', 'EXTRANET', 'DMZ', 'CLOUD_VPC', 'REMOTE_ENDPOINT']
  return <section className="zone-distribution" aria-label="Zone threat distribution"><div className="zone-distribution-heading"><span>ZONE THREAT DISTRIBUTION</span><strong>{logs.length} EVENTS</strong></div><div className="zone-distribution-list">{zones.map((zone) => <div key={zone}><span>{zone.replaceAll('_', ' ')}</span><b>{logs.filter((log) => log.networkZone === zone).length}</b></div>)}</div></section>
}

function LogRow({ log }: { log: LogEntry }) {
  return <tr><td className="mono-cell">{new Date(log.timestamp).toLocaleTimeString('en-US', { hour12: false })}</td><td><SeverityBadge severity={log.severity} /></td><td><strong className="event-name">{log.eventCategory.replaceAll('_', ' ')}</strong><small className="event-summary">{log.rawPayload}</small></td><td className="mono-cell ip-cell">{log.sourceIp}<span> → </span>{log.destIp}</td><td><div className="node-cell"><strong>{log.targetNode.hostname}</strong><small>{log.targetNode.nodeType} · <span className="zone-tag">{log.networkZone}</span></small>{log.targetNode.isIsolated && <span className="isolation-badge">ISOLATED</span>}</div></td><td><span className="protocol-tag">{log.protocol}</span></td><td><span className={`status-label ${log.status.toLowerCase()}`}><i />{log.status.replaceAll('_', ' ')}</span></td></tr>
}

function Incidents({ incidents, onSelect, onContain }: { incidents: Incident[]; onSelect: (incident: Incident) => void; onContain: (incident: Incident) => void }) {
  const [filter, setFilter] = useState('ALL')
  const visible = incidents.filter((incident) => filter === 'ALL' || incident.severity === filter)
  return <section className="panel full-panel"><div className="panel-header"><div><div className="panel-title">Incident register <span className="small-count">{visible.length}</span></div><div className="panel-subtitle">Prioritized cases from across the environment</div></div><div className="table-tools"><select className="select-button native-select" value={filter} onChange={(event) => setFilter(event.target.value)}><option value="ALL">All severities</option>{(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((item) => <option key={item}>{item}</option>)}</select><button className="button-secondary" onClick={() => onSelect(incidents[0])}><FileSearch size={15} />Open case</button></div></div><div className="table-scroll"><table className="data-table incident-table"><thead><tr><th>INCIDENT</th><th>SEVERITY</th><th>STATUS</th><th>AFFECTED ASSET</th><th>MITRE ATT&amp;CK</th><th>OPENED</th><th /></tr></thead><tbody>{visible.map((incident) => <tr key={incident._id} onClick={() => onSelect(incident)}><td><strong className="incident-name">{incident.title}</strong><small className="event-summary">{incident._id} · {incident.description}</small></td><td><span className={`severity-tag ${severityClass[incident.severity]}`}>{incident.severity}</span></td><td><span className={`incident-status status-${incident.status.toLowerCase()}`}>{incident.status}</span></td><td className="mono-cell">{incident.affectedHosts[0]}</td><td className="mitre-cell">{incident.mitreAttackTechnique}</td><td className="mono-cell">{relativeTime(incident.createdAt)}</td><td><button className="icon-button" aria-label={`Open ${incident._id}`} onClick={(event) => { event.stopPropagation(); onSelect(incident) }}><ArrowUpRight size={16} /></button></td></tr>)}</tbody></table></div><div className="table-footer"><span>{visible.length} incidents shown</span><span>Containment actions require elevated clearance</span></div></section>
}

function Hunting({ logs, zoneFilter, setZoneFilter }: { logs: LogEntry[]; zoneFilter: NetworkZone | 'ALL'; setZoneFilter: (zone: NetworkZone | 'ALL') => void }) {
  const [ip, setIp] = useState('')
  const [severity, setSeverity] = useState('ALL')
  const [searched, setSearched] = useState(false)
  const results = logs.filter((log) => (!ip || `${log.sourceIp}${log.destIp}`.includes(ip))
    && (severity === 'ALL' || log.severity === severity)
    && (zoneFilter === 'ALL' || log.networkZone === zoneFilter))
  return <div className="hunting-layout">
    <section className="panel query-panel">
      <div className="panel-header"><div><div className="panel-title">Query builder</div><div className="panel-subtitle">Compose a telemetry search</div></div><FileSearch size={16} className="muted-icon" /></div>
      <div className="query-fields">
        <label>Source or destination IP<div className="input-wrap"><Network size={15} /><input value={ip} onChange={(event) => setIp(event.target.value)} placeholder="e.g. 10.24.8.42" /></div></label>
        <div className="field-row"><label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="ALL">Any severity</option>{(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((item) => <option key={item}>{item}</option>)}</select></label><label>Indicator type<select defaultValue="ANY"><option value="ANY">Any indicator</option><option>IP address</option><option>Domain</option><option>SHA-256 hash</option></select></label></div>
        <div className="field-row"><label>From<input type="datetime-local" defaultValue="2026-11-11T08:00" /></label><label>To<input type="datetime-local" defaultValue="2026-11-11T11:00" /></label></div>
        <button className="button-primary query-submit" onClick={() => setSearched(true)}><Search size={15} />Run hunt</button>
      </div>
      <div className="saved-hunts"><span>SAVED HUNTS</span><button onClick={() => { setIp('45.83.64.21'); setSeverity('HIGH'); setSearched(true) }}><Crosshair size={14} />Potential C2 beaconing <ArrowUpRight size={13} /></button><button onClick={() => { setIp('10.24.'); setSeverity('CRITICAL'); setSearched(true) }}><Database size={14} />High-volume egress <ArrowUpRight size={13} /></button></div>
    </section>
    <section className="panel hunt-results">
      <div className="panel-header"><div><div className="panel-title">{searched ? 'Hunt results' : 'Threat landscape'}</div><div className="panel-subtitle">{searched ? `${results.length} matching events` : 'Correlated telemetry · trailing 24 hours'}</div></div><button className="button-quiet"><Filter size={14} />Filters</button></div>
      <ZoneFilterBar selected={zoneFilter} onChange={setZoneFilter} />
      {searched ? <div className="hunt-result-list">{results.length ? results.map((log) => <div className="hunt-result" key={log._id}><span className={`priority-mark ${severityClass[log.severity]}`} /><div><strong>{log.eventCategory.replaceAll('_', ' ')}</strong><small>{log.sourceIp} → {log.destIp} · {new Date(log.timestamp).toLocaleString()}<br />{log.targetNode.hostname} · {log.targetNode.nodeType} · <span className="zone-tag">{log.networkZone}</span>{log.targetNode.isIsolated && <span className="isolation-badge">ISOLATED</span>}</small></div><span className={`severity-tag ${severityClass[log.severity]}`}>{log.severity}</span></div>) : <div className="empty-state">No matching events in the current window.</div>}</div> : <><div className="hunt-chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chartData}><defs><linearGradient id="huntFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#b7f36b" stopOpacity={0.2} /><stop offset="100%" stopColor="#b7f36b" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#2a383d" vertical={false} /><XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fill: '#77878a', fontSize: 10 }} /><YAxis tickLine={false} axisLine={false} tick={{ fill: '#77878a', fontSize: 10 }} /><Area type="monotone" dataKey="events" stroke="#b7f36b" fill="url(#huntFill)" /></AreaChart></ResponsiveContainer></div><div className="indicator-list"><div className="indicator-list-heading">RECENT INDICATOR MATCHES <span>12 MATCHES</span></div>{[{ ip: '45.83.64.21', type: 'IP ADDRESS', desc: 'Known command and control node', level: 'MALICIOUS' }, { ip: 'cdn-updater-sync.net', type: 'DOMAIN', desc: 'Newly registered · first seen 2h ago', level: 'SUSPICIOUS' }, { ip: '185.199.110.153', type: 'IP ADDRESS', desc: 'Unusual egress volume detected', level: 'SUSPICIOUS' }].map((ioc) => <div className="indicator-row" key={ioc.ip}><Globe2 size={15} /><div><strong>{ioc.ip}</strong><small>{ioc.type} · {ioc.desc}</small></div><span className={ioc.level === 'MALICIOUS' ? 'ioc-bad' : 'ioc-suspicious'}>{ioc.level}</span></div>)}</div></>}
    </section>
  </div>
}

function EventStream({ logs, query, setQuery, severity, setSeverity, streaming, setStreaming }: { logs: LogEntry[]; query: string; setQuery: (value: string) => void; severity: string; setSeverity: (value: string) => void; streaming: boolean; setStreaming: (value: boolean) => void }) {
  return <section className="panel full-panel stream-page"><div className="panel-header"><div><div className="panel-title live-title"><span className="live-dot" />Security events</div><div className="panel-subtitle">Normalized telemetry · newest first</div></div><button className="button-quiet" onClick={() => setStreaming(!streaming)}>{streaming ? 'Pause stream' : 'Resume stream'} <span>{streaming ? 'Ⅱ' : '▶'}</span></button></div><div className="stream-toolbar"><div className="input-wrap"><Search size={15} /><input id="global-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search IP, event category, payload..." /></div><select className="select-button native-select" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="ALL">All severities</option>{(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((item) => <option key={item}>{item}</option>)}</select><span className="result-count">{logs.length} events</span></div><div className="table-scroll"><table className="data-table"><thead><tr><th>TIME</th><th>SEVERITY</th><th>EVENT</th><th>SOURCE → DESTINATION</th><th>NETWORK NODE / ZONE</th><th>PROTOCOL</th><th>STATUS</th></tr></thead><tbody>{logs.map((log) => <LogRow key={log._id} log={log} />)}</tbody></table>{!logs.length && <div className="empty-state">No events match these filters.</div>}</div><div className="table-footer"><span>Showing {logs.length} events</span><span>Retention policy: 90 days <CircleHelp size={13} /></span></div></section>
}

function AccessControl({ role, setRole, notify, allowPreview }: { role: Role; setRole: (role: Role) => void; notify: (message: string) => void; allowPreview: boolean }) {
  const roles: { name: Role; title: string; level: string; description: string; color: string }[] = [
    { name: 'ADMIN', title: 'Administrator', level: 'SYSTEM', description: 'Full system access, including staff and RBAC management.', color: 'role-admin' },
    { name: 'SOC_ANALYST_L1', title: 'SOC Analyst · L1', level: 'TIER 1', description: 'Monitor alerts, triage events, and escalate incidents.', color: 'role-green' },
    { name: 'THREAT_HUNTER_L2', title: 'Threat Hunter · L2', level: 'TIER 2', description: 'Investigate threats and initiate approved containment.', color: 'role-blue' },
    { name: 'INCIDENT_COMMANDER', title: 'Incident Commander', level: 'TIER 3', description: 'Coordinate major response and authorize isolation.', color: 'role-amber' },
    { name: 'CISO', title: 'Chief Information Security Officer', level: 'EXECUTIVE', description: 'Read-only oversight of risk and security posture.', color: 'role-violet' },
  ]
  return <div className="access-layout">
    <section className="panel role-panel">
      <div className="panel-header"><div><div className="panel-title">Clearance levels</div><div className="panel-subtitle">{allowPreview ? 'Role selection is a local UI preview only.' : 'The signed-in account role is enforced.'}</div></div><LockKeyhole size={16} className="muted-icon" /></div>
      <div className="role-list">{roles.map((item) => <button className={`role-row ${role === item.name ? 'role-selected' : ''}`} key={item.name} onClick={() => setRole(item.name)} disabled={!allowPreview}><span className={`role-icon ${item.color} ${item.name === 'ADMIN' ? 'staff-role-badge' : ''}`}><Users size={17} /></span><span className="role-info"><strong>{item.title}<i>{item.level}</i></strong><small>{item.description}</small></span>{role === item.name ? <span className="selected-check"><ShieldCheck size={16} />Active</span> : <ArrowUpRight size={15} className="muted-icon" />}</button>)}</div>
    </section>
    <section className="panel permission-panel">
      <div className="panel-header"><div><div className="panel-title">Permission boundary test</div><div className="panel-subtitle">Try the current clearance against protected actions</div></div><Shield size={16} className="muted-icon" /></div>
      <div className="permission-checks">{[{ action: 'View security events', allowed: true, icon: Activity }, { action: 'Create incident record', allowed: true, icon: BookOpenCheck }, { action: 'Isolate network host', allowed: role === 'ADMIN' || role === 'THREAT_HUNTER_L2' || role === 'INCIDENT_COMMANDER', icon: Blocks }, { action: 'Blacklist network indicator', allowed: role === 'ADMIN' || role === 'THREAT_HUNTER_L2' || role === 'INCIDENT_COMMANDER', icon: Globe2 }].map(({ action, allowed, icon: Icon }) => <div className="permission-row" key={action}><Icon size={15} /><span>{action}</span><span className={allowed ? 'permission-allow' : 'permission-deny'}>{allowed ? 'ALLOWED' : 'RESTRICTED'}</span></div>)}</div>
      <button className="button-secondary test-button" onClick={() => notify(role === 'SOC_ANALYST_L1' || role === 'CISO' ? '403 · Insufficient clearance. Requires L2 or Incident Commander.' : '200 · Clearance verified. Action would be audited.')}>Test protected action <ArrowUpRight size={14} /></button>
    </section>
    <div className="access-note"><LockKeyhole size={15} /><span><strong>Enforcement happens server-side.</strong> The API revalidates the signed-in user and current role on every protected request.</span></div>
  </div>
}

function IncidentModal({ incident, onClose, onContain, onEscalate, onResolve, role }: {
  incident: Incident
  onClose: () => void
  onContain: (incident: Incident) => void
  onEscalate: (incident: Incident, note: string) => Promise<boolean>
  onResolve: (incident: Incident, note: string) => Promise<boolean>
  role: Role
}) {
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [noteError, setNoteError] = useState('')
  const escalationOrder: Exclude<Role, 'ADMIN'>[] = ['SOC_ANALYST_L1', 'THREAT_HUNTER_L2', 'INCIDENT_COMMANDER', 'CISO']
  const escalationRole = incident.escalationRole ?? 'SOC_ANALYST_L1'
  const escalationHistory = incident.escalationHistory ?? []
  const currentTierIndex = escalationOrder.indexOf(escalationRole)
  const nextTier = escalationOrder[currentTierIndex + 1]
  const active = incident.status !== 'RESOLVED' && incident.status !== 'CLOSED'
  const authorized = role === 'ADMIN' || role === 'INCIDENT_COMMANDER' || role === 'THREAT_HUNTER_L2'
  const canEscalate = role === 'ADMIN' || role === escalationRole
  const canResolve = canViewIncident(role, incident)

  async function submit(action: 'escalate' | 'resolve') {
    const trimmedNote = note.trim()
    if (trimmedNote.length < 10) {
      setNoteError('Add at least 10 characters of meaningful notes.')
      return
    }
    if (action === 'escalate' && !nextTier) {
      setNoteError('This incident is already at the highest escalation tier (CISO).')
      return
    }
    if (action === 'escalate' && !canEscalate) {
      setNoteError('Only staff at the incident’s current tier or an Admin can escalate it.')
      return
    }
    if (action === 'resolve' && !canResolve) {
      setNoteError('You can only resolve incidents visible to your tier.')
      return
    }
    setBusy(true)
    setNoteError('')
    try {
      const succeeded = action === 'escalate'
        ? await onEscalate(incident, trimmedNote)
        : await onResolve(incident, trimmedNote)
      if (succeeded) setNote('')
    } finally {
      setBusy(false)
    }
  }

  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onClose() }}>
    <section className="incident-modal">
      <div className="modal-header"><div><span className="eyebrow">INCIDENT DETAIL <span className="modal-id">{incident._id}</span></span><h2>{incident.title}</h2></div><button className="icon-button" onClick={onClose} aria-label="Close details"><X size={18} /></button></div>
      <p className="modal-description">{incident.description}</p>
      <div className="modal-tags"><span className={`severity-tag ${severityClass[incident.severity]}`}>{incident.severity}</span><span className={`incident-status status-${incident.status.toLowerCase()}`}>{incident.status}</span><span className="mono-cell">Opened {relativeTime(incident.createdAt)}</span></div>
      <div className="modal-section"><span className="modal-label">AFFECTED ASSETS</span><div className="asset-list">{incident.affectedHosts.map((host) => <span key={host}><Network size={14} />{host}</span>)}</div></div>
      <div className="modal-section"><span className="modal-label">MITRE ATT&amp;CK MAPPING</span><div className="mitre-mapping"><Crosshair size={15} /><strong>{incident.mitreAttackTechnique}</strong><ArrowUpRight size={14} /></div></div>
      <div className="escalation-summary"><span className="modal-label">CURRENT ESCALATION TIER</span><strong>{escalationRole.replaceAll('_', ' ')}</strong>{incident.assignedAnalyst && <small>Assigned to {incident.assignedAnalyst.fullName}</small>}{!incident.assignedAnalyst && escalationHistory.length > 0 && <small>Queued for an active {escalationRole.replaceAll('_', ' ')} responder</small>}</div>
      <div className="timeline">
        <span className="modal-label">ACTIVITY TIMELINE</span>
        <div><i /><span><strong>Incident opened</strong><small>{new Date(incident.createdAt).toLocaleString()} · Detection engine</small></span></div>
        {escalationHistory.map((entry, index) => <div key={`${entry.timestamp}-${index}`}><i /><span><strong>Escalated to {entry.toRole.replaceAll('_', ' ')}</strong><small>{entry.note} · {entry.author} · {new Date(entry.timestamp).toLocaleString()}</small></span></div>)}
        {incident.resolutionNote && <div><i /><span><strong>Resolved</strong><small>{incident.resolutionNote} · {incident.resolvedAt ? new Date(incident.resolvedAt).toLocaleString() : ''}</small></span></div>}
        {incident.status === 'CONTAINED' && <div><i /><span><strong>Simulated containment recorded</strong><small>Action logged to incident timeline</small></span></div>}
      </div>
      {active && <div className="incident-disposition">
        <label htmlFor="incident-action-note">{nextTier ? `Escalation or resolution notes (required)` : 'Resolution notes (required)'}</label>
        <textarea id="incident-action-note" value={note} onChange={(event) => { setNote(event.target.value); setNoteError('') }} maxLength={1000} minLength={10} placeholder="Document evidence, actions taken, and why this incident should be escalated or resolved..." />
        <small>10–1000 characters. Notes are added to the incident audit trail.</small>
        {noteError && <span className="incident-note-error" role="alert">{noteError}</span>}
        <div className="incident-disposition-actions">
          {nextTier && canEscalate && <button className="button-secondary" disabled={busy} onClick={() => void submit('escalate')}><ArrowUpRight size={14} />{busy ? 'Saving...' : `Escalate to ${nextTier.replaceAll('_', ' ')}`}</button>}
          {canResolve && <button className="button-primary resolve-button" disabled={busy} onClick={() => void submit('resolve')}><ShieldCheck size={14} />{busy ? 'Saving...' : 'Close as resolved'}</button>}
        </div>
      </div>}
      <div className="modal-actions"><button className="button-secondary" onClick={onClose}>Close details</button>{active && <button className="button-primary" disabled={!authorized || incident.status === 'CONTAINED'} title={!authorized ? 'Requires Threat Hunter L2 or Incident Commander' : ''} onClick={() => onContain(incident)}><Blocks size={15} />{incident.status === 'CONTAINED' ? 'Contained' : 'Simulate host isolation'}</button>}</div>
      {!authorized && active && <small className="modal-permission"><LockKeyhole size={12} /> Host isolation requires THREAT_HUNTER_L2 or INCIDENT_COMMANDER clearance</small>}
    </section>
  </div>
}

function LoginModal({ onClose, onLogin }: { onClose: () => void; onLogin: (email: string, password: string) => Promise<void> }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await onLogin(email, password)
      onClose()
    } catch {
      setError('Unable to sign in. Check your credentials and API connection.')
    } finally {
      setBusy(false)
    }
  }

  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><section className="login-modal"><div className="modal-header"><div><span className="eyebrow">SECURE API SESSION</span><h2>Connect to operations</h2></div><button className="icon-button" onClick={onClose} aria-label="Close sign in"><X size={18} /></button></div><p className="modal-description">Sign in with your SOC analyst account to access protected incidents and live telemetry.</p><form onSubmit={submit}><label>Email address<input type="email" autoComplete="username" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="analyst@organization.com" /></label><label>Password<input type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Your account password" /></label>{error && <div className="login-error">{error}</div>}<div className="modal-actions"><button type="button" className="button-secondary" onClick={onClose}>Cancel</button><button type="submit" className="button-primary" disabled={busy}><LockKeyhole size={14} />{busy ? 'Connecting...' : 'Connect securely'}</button></div></form></section></div>
}

function relativeTime(value: string) {
  const minutes = Math.max(1, Math.floor((Date.now() - new Date(value).getTime()) / 60000))
  return minutes < 60 ? `${minutes}m ago` : `${Math.floor(minutes / 60)}h ago`
}

function formatCountdown(nextRunAt: string, now: number) {
  const seconds = Math.max(0, Math.floor((new Date(nextRunAt).getTime() - now) / 1000))
  const hours = Math.floor(seconds / 3600).toString().padStart(2, '0')
  const minutes = Math.floor((seconds % 3600) / 60).toString().padStart(2, '0')
  const remainingSeconds = (seconds % 60).toString().padStart(2, '0')
  return `${hours}:${minutes}:${remainingSeconds}`
}

export default App