'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useSensorTransportStatus } from '@/lib/api/sensor-pairing-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'
import { cn } from '@/lib/utils'

/**
 * How sensors reach this platform (api docs/rfcs/RFC-059 T15): the gRPC
 * binding is offered only while the platform's own probe reaches it; the
 * reason is shown when it is not. Platform configuration, no tenant data.
 */
export function SensorTransportStatusLine({ className }: { className?: string }) {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.SensorsRead)
  const { data } = useSensorTransportStatus(canRead)
  if (!canRead || !data) return null

  let text: string
  if (data.mode === 'off') {
    text = t('sensors.transportStatus.off')
  } else if (data.grpc.state === 'advertised') {
    text = t('sensors.transportStatus.grpc', undefined, { endpoint: data.grpc.endpoint ?? '' })
  } else if (data.grpc.state === 'pending') {
    text = t('sensors.transportStatus.pending')
  } else {
    text = t('sensors.transportStatus.httpsOnly')
  }
  return (
    <p
      className={cn('text-xs text-muted-foreground', className)}
      data-testid="sensor-transport-status"
    >
      {text}
      {data.mode !== 'off' && data.grpc.state === 'unavailable' && data.grpc.reason ? (
        <span className="font-mono"> ({data.grpc.reason})</span>
      ) : null}
    </p>
  )
}
