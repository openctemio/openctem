'use client'

/**
 * Parts shared by the Tenable connector view and the paused scanner-imports
 * view of Settings > Integrations > Vulnerability scanners.
 */

import { Badge } from '@/components/ui/badge'
import type {
  Integration,
  IntegrationStatus,
} from '@/features/integrations/types/integration.types'

export function getConfigString(integration: Integration, key: string): string {
  const config = integration.config as Record<string, unknown> | undefined
  return (config?.[key] as string) ?? ''
}

export function StatusBadge({ status }: { status: IntegrationStatus }) {
  const config: Record<string, { className: string; label: string }> = {
    connected: {
      className: 'bg-success/10 text-success border-success/20',
      label: 'Connected',
    },
    disconnected: { className: 'bg-muted text-muted-foreground', label: 'Not Connected' },
    error: {
      className: 'bg-destructive/10 text-destructive border-destructive/20',
      label: 'Error',
    },
    pending: {
      className: 'bg-warning/10 text-warning border-warning/20',
      label: 'Pending',
    },
    expired: {
      className: 'bg-warning/15 text-warning border-warning/30',
      label: 'Expired',
    },
    disabled: { className: 'bg-muted text-muted-foreground', label: 'Disabled' },
  }
  const { className, label } = config[status] ?? config.disconnected
  return (
    <Badge variant="outline" className={className}>
      {label}
    </Badge>
  )
}
