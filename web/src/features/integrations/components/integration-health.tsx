'use client'

import { useTranslation } from '@/context/i18n-provider'
import { HealthStatus } from '@/components/ui/health-status'
import { integrationHealth } from '../lib/integration-health'

/** The connection status of an integration (hub, SCM, notification, ticketing, scanner). */
export function IntegrationHealth({
  status,
  className,
}: {
  status: string | null | undefined
  className?: string
}) {
  const { t } = useTranslation()
  const h = integrationHealth(status)
  return (
    <HealthStatus
      state={h.state}
      value={status ?? undefined}
      label={t(h.labelKey, h.label)}
      className={className}
    />
  )
}
