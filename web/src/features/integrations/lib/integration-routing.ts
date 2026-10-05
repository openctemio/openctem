/**
 * Which settings page manages an integration.
 *
 * SIEM destinations (Splunk HEC) are stored as notification-category
 * integrations, but they are managed on the SIEM page: the Notification
 * channels edit dialog has no HEC fields and falls back to "Webhook URL", so
 * typing a URL there replaced the encrypted HEC token (23a B19). Every page
 * that lists or links integrations goes through these helpers.
 */
import type { Integration, IntegrationCategory } from '../types/integration.types'

export const SIEM_PROVIDERS: ReadonlySet<string> = new Set(['splunk'])

export function isSiemIntegration(i: Pick<Integration, 'provider'>): boolean {
  return SIEM_PROVIDERS.has(i.provider)
}

/** Notification channels proper: notification integrations that are not SIEM. */
export function notificationChannelsOnly<T extends Pick<Integration, 'provider'>>(
  list: readonly T[]
): T[] {
  return list.filter((i) => !isSiemIntegration(i))
}

/** SIEM destinations only. */
export function siemIntegrationsOnly<T extends Pick<Integration, 'provider'>>(
  list: readonly T[]
): T[] {
  return list.filter((i) => isSiemIntegration(i))
}

const CATEGORY_HREF: Record<IntegrationCategory, string> = {
  scm: '/settings/integrations/scm',
  security: '/settings/integrations/scanners',
  ticketing: '/settings/integrations/ticketing',
  cloud: '/settings/integrations',
  notification: '/settings/integrations/notifications',
}

export function integrationManageHref(i: Pick<Integration, 'provider' | 'category'>): string {
  if (isSiemIntegration(i)) return '/settings/integrations/siem'
  return CATEGORY_HREF[i.category] ?? '/settings/integrations'
}
