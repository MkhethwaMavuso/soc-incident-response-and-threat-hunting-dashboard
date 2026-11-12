import type { Severity } from '../types'

const classes: Record<Severity, string> = {
  LOW: 'severity-low',
  MEDIUM: 'severity-medium',
  HIGH: 'severity-high',
  CRITICAL: 'severity-critical',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-tag ${classes[severity]}`}>{severity}</span>
}