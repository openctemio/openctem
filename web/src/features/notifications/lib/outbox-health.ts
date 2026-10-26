/**
 * The state of a notification outbox entry as the machine state it reports
 * (research 247). Colour-free: HealthStatus owns the colours.
 */

import type { HealthState } from '@/lib/health-colors'
import type { OutboxStatus } from '../types/notification-outbox.types'

export const OUTBOX_HEALTH: Record<
  OutboxStatus,
  { state: HealthState; labelKey: string; label: string }
> = {
  pending: {
    state: 'queued',
    labelKey: 'notificationChannels.outbox.status.pending',
    label: 'Pending',
  },
  processing: {
    state: 'run',
    labelKey: 'notificationChannels.outbox.status.processing',
    label: 'Processing',
  },
  completed: {
    state: 'ok',
    labelKey: 'notificationChannels.outbox.status.completed',
    label: 'Completed',
  },
  failed: { state: 'down', labelKey: 'notificationChannels.outbox.status.failed', label: 'Failed' },
  dead: { state: 'down', labelKey: 'notificationChannels.outbox.status.dead', label: 'Dead' },
}
