export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type IncidentStatus = 'OPEN' | 'CONTAINED' | 'RESOLVED' | 'CLOSED'
export type LogStatus = 'UNRESOLVED' | 'INVESTIGATING' | 'MITIGATED' | 'FALSE_POSITIVE'
export type Role = 'ADMIN' | 'CISO' | 'INCIDENT_COMMANDER' | 'THREAT_HUNTER_L2' | 'SOC_ANALYST_L1'
export type NetworkZone = 'INTRANET' | 'EXTRANET' | 'DMZ' | 'CLOUD_VPC' | 'REMOTE_ENDPOINT'
export type NodeType = 'WORKSTATION' | 'DATABASE_SERVER' | 'WEB_GATEWAY' | 'IOT_SENSOR' | 'DOMAIN_CONTROLLER'
export type StaffStatus = 'ACTIVE' | 'SUSPENDED' | 'ON_LEAVE'
export type Department = 'Threat Hunting' | 'Incident Response' | 'Network Security' | 'Governance & Risk'

export interface TargetNode {
  hostname: string
  ipAddress: string
  nodeType: NodeType
  os: string
  isIsolated: boolean
}

export interface LogEntry {
  _id: string
  timestamp: string
  sourceIp: string
  destIp: string
  protocol: string
  severity: Severity
  eventCategory: string
  rawPayload: string
  status: LogStatus
  networkZone: NetworkZone
  targetNode: TargetNode
  mitreAttackTechnique: string
}

export interface Incident {
  _id: string
  title: string
  description: string
  severity: Severity
  status: IncidentStatus
  affectedHosts: string[]
  mitreAttackTechnique: string
  createdAt: string
  networkZone: NetworkZone
  targetNode: TargetNode
  escalationRole: Exclude<Role, 'ADMIN'>
  escalationHistory: IncidentEscalation[]
  resolutionNote?: string
  resolvedAt?: string
  assignedAnalyst?: { fullName: string; email: string; role: Role }
}

export interface IncidentEscalation {
  fromRole: Exclude<Role, 'ADMIN'>
  toRole: Exclude<Role, 'ADMIN'>
  note: string
  author: string
  timestamp: string
}

export interface StaffMember {
  _id: string
  fullName: string
  email: string
  badgeId: string
  role: Role
  department: Department
  status: StaffStatus
  lastLogin?: string
  createdAt: string
  updatedAt: string
}

export interface ThreatIndicator {
  _id: string
  indicatorType: 'IP' | 'DOMAIN' | 'HASH_SHA256' | 'URL'
  value: string
  threatLevel: 'SUSPICIOUS' | 'MALICIOUS' | 'KNOWN_BAD'
  confidenceScore: number
  tags: string[]
}