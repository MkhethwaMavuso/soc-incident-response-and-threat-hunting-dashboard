import type { ReactNode } from 'react'

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle: string; actions: ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line" />SECURITY OPERATIONS CENTER <span className="date-label">WED, 11 NOV 2026</span></div><h1>{title}</h1><p>{subtitle}</p></div><div className="heading-actions">{actions}</div></div>
}