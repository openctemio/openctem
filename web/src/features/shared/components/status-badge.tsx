'use client'

import { HealthStatus } from '@/components/ui/health-status'
import { useTranslation } from '@/context/i18n-provider'
import type { HealthState } from '@/lib/health-colors'
import type { Status } from '../types'

interface StatusBadgeProps {
  status: Status
  className?: string
}

/** The lifecycle of an asset or a run, as a machine state. */
const STATUS_STATE: Record<Status, { state: HealthState; label: string }> = {
  active: { state: 'ok', label: 'Active' },
  stale: { state: 'warn', label: 'Stale' },
  inactive: { state: 'off', label: 'Inactive' },
  archived: { state: 'off', label: 'Archived' },
  pending: { state: 'queued', label: 'Pending' },
  completed: { state: 'ok', label: 'Completed' },
  failed: { state: 'down', label: 'Failed' },
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const { t } = useTranslation()
  const config = STATUS_STATE[status]
  return (
    <HealthStatus
      state={config.state}
      value={status}
      label={t(`labels.status.${status}`, config.label)}
      className={className}
    />
  )
}
