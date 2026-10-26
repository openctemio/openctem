/**
 * An integration's connection status as the machine state it reports
 * (research 247): one map for the hub, the SCM, notification, ticketing,
 * scanner and SIEM pages. Colour-free: HealthStatus owns the colours.
 */

import type { HealthState } from '@/lib/health-colors'

export const INTEGRATION_STATUSES = [
  'connected',
  'pending',
  'error',
  'expired',
  'disabled',
  'disconnected',
] as const
export type IntegrationHealthStatus = (typeof INTEGRATION_STATUSES)[number]

export const INTEGRATION_HEALTH: Record<
  IntegrationHealthStatus,
  { state: HealthState; labelKey: string; label: string }
> = {
  connected: { state: 'ok', labelKey: 'integrationsHub.status.connected', label: 'Connected' },
  pending: { state: 'queued', labelKey: 'integrationsHub.status.pending', label: 'Pending' },
  error: { state: 'down', labelKey: 'integrationsHub.status.error', label: 'Error' },
  expired: { state: 'down', labelKey: 'integrationsHub.status.expired', label: 'Expired' },
  disabled: { state: 'off', labelKey: 'integrationsHub.status.disabled', label: 'Disabled' },
  disconnected: {
    state: 'unknown',
    labelKey: 'integrationsHub.status.disconnected',
    label: 'Disconnected',
  },
}

/** The entry for a status; anything unknown reads as not connected. */
export function integrationHealth(status: string | null | undefined) {
  return INTEGRATION_HEALTH[status as IntegrationHealthStatus] ?? INTEGRATION_HEALTH.disconnected
}
