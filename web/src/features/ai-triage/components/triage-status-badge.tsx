'use client'

import { HealthStatus } from '@/components/ui/health-status'
import { useTranslation } from '@/context/i18n-provider'
import type { TriageStatus } from '../types'
import { TRIAGE_STATUS_CONFIG } from '../types'

interface TriageStatusBadgeProps {
  status: TriageStatus
  className?: string
}

/** An AI triage job's status: the shared machine-state indicator. */
export function TriageStatusBadge({ status, className }: TriageStatusBadgeProps) {
  const { t } = useTranslation()
  const config = TRIAGE_STATUS_CONFIG[status] ?? {
    label: String(status),
    health: 'unknown' as const,
  }
  return (
    <HealthStatus
      state={config.health}
      label={t(`findings.aiTriage.status.${status}`, config.label)}
      value={status}
      className={className}
    />
  )
}
