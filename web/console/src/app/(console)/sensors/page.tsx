'use client'

import { Info } from 'lucide-react'
import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader, PageStack } from '@/features/shared'
import {
  createSharedSensorEnrollmentToken,
  useSharedSensorsSetting,
} from '@console/features/admin-console/api/use-scan-policy'
import { useInstanceScanZones } from '@console/features/admin-console/api/use-instance-scan-zones'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { InstanceScanZonesCard } from '@console/features/admin-console/components/instance-scan-zones-card'
import { SharedSensorEnrollCard } from '@console/features/admin-console/components/shared-sensor-enroll-card'
import { SharedFleetPanel } from '@console/features/admin-console/components/shared-fleet-panels'
import { adminHas } from '@console/features/admin-console/types'

/**
 * Platform sensors: the sensors the platform itself owns (feed relay, passive
 * discovery, AI worker, shared scanners), their enrollment, state and scan
 * zones. It is not behind the shared-scanning rollout gate: that gate only
 * decides whether organizations may use these sensors, so a platform sensor
 * can be connected and watched before shared scanning is turned on. Any
 * administrator reads; a super admin enrolls, pauses, retires and edits zones
 * (the API enforces it with a reason and a fresh code). Shared scanning for
 * organizations stays in Scanning > Platform scanning.
 */
export default function PlatformSensorsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const canEdit = adminHas(me, 'platform.sensors.manage')
  const shared = useSharedSensorsSetting()
  const zones = useInstanceScanZones()
  const gateClosed = !!shared.data && !shared.data.ready
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.sensors.pageTitle', 'Platform sensors')}
          description={t(
            'admin.sensors.pageDesc',
            'Sensors the platform owns. Organizations never see them by name.'
          )}
        />
        {gateClosed && (
          <p
            className="flex items-start gap-2 text-sm text-muted-foreground"
            data-testid="sensors-shared-scanning-closed"
          >
            <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
            {t(
              'admin.sensors.sharedClosed',
              'Organizations cannot use shared scanning in this release yet. Sensors connected now serve platform roles (feed relay, passive discovery, AI worker) and start scanning for organizations when shared scanning is turned on.'
            )}
          </p>
        )}
        <SharedSensorEnrollCard
          canEdit={canEdit}
          onIssue={({ name, ttlMinutes, reason, code }) =>
            createSharedSensorEnrollmentToken({
              name,
              ttl_minutes: ttlMinutes,
              reason,
              totp_code: code,
            })
          }
        />
        <SharedFleetPanel />
        {zones.error ? (
          <ErrorState
            title={t('admin.instanceZones.errorTitle')}
            error={zones.error}
            onRetry={() => void zones.mutate()}
          />
        ) : zones.isLoading || !zones.data ? (
          <Skeleton className="h-40 w-full" />
        ) : (
          <InstanceScanZonesCard
            zones={zones.data.items ?? []}
            canEdit={canEdit}
            onChanged={() => zones.mutate()}
          />
        )}
      </PageStack>
    </Main>
  )
}
