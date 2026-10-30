'use client'

/**
 * Parts shared by the Tenable connector view and the paused scanner-imports
 * view of Settings > Integrations > Vulnerability scanners.
 */

import { IntegrationHealth } from '../integration-health'
import type {
  Integration,
  IntegrationStatus,
} from '@/features/integrations/types/integration.types'

export function getConfigString(integration: Integration, key: string): string {
  const config = integration.config as Record<string, unknown> | undefined
  return (config?.[key] as string) ?? ''
}

export function StatusBadge({ status }: { status: IntegrationStatus }) {
  return <IntegrationHealth status={status} />
}
