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
const STATUS_STATE: Record<Status, HealthState> = {
  active: 'ok',
  stale: 'warn',
  inactive: 'off',
  archived: 'off',
  pending: 'queued',
  completed: 'ok',
  failed: 'down',
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const { t } = useTranslation()
  const labels: Record<Status, string> = {
    active: t('labels.status.active', 'Active'),
    stale: t('labels.status.stale', 'Stale'),
    inactive: t('labels.status.inactive', 'Inactive'),
    archived: t('labels.status.archived', 'Archived'),
    pending: t('labels.status.pending', 'Pending'),
    completed: t('labels.status.completed', 'Completed'),
    failed: t('labels.status.failed', 'Failed'),
  }
  return (
    <HealthStatus
      state={STATUS_STATE[status]}
      value={status}
      label={labels[status]}
      className={className}
    />
  )
}
