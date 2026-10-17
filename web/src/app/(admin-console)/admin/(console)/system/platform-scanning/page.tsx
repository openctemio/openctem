'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import {
  createSharedSensorEnrollmentToken,
  savePlatformSensorProof,
  saveSharedSensorAnomaly,
  saveSharedSensorInternalZones,
  saveSharedSensorsEgress,
  saveSharedSensorsSetting,
  usePlatformSensorProof,
  useSharedSensorAnomaly,
  useSharedSensorInternalZones,
  useSharedSensorsEgress,
  useSharedSensorsSetting,
} from '@/features/admin-console/api/use-scan-policy'
import { PlatformSensorProofForm } from '@/features/admin-console/components/platform-sensor-proof-form'
import { SharedSensorAnomalyForm } from '@/features/admin-console/components/shared-sensor-anomaly-form'
import { SharedSensorEnrollCard } from '@/features/admin-console/components/shared-sensor-enroll-card'
import { SharedSensorsForm } from '@/features/admin-console/components/shared-sensors-form'
import { SharedSensorsEgressForm } from '@/features/admin-console/components/shared-sensors-egress-form'
import { adminCan } from '@/features/admin-console/types'

/**
 * System -> Platform scanning: shared sensors on this instance (RFC-100 §5),
 * the egress addresses organizations allowlist (RFC-100 §9) and whether platform sensors need a verified domain before they scan a
 * target (RFC-054 §8.1), whether shared sensors may scan internal zones
 * (RFC-100 §6.1) and the anomaly alert thresholds (RFC-100 §9). Until a value
 * is stored the deployment default applies (MANAGED_SERVICE changes the
 * defaults, RFC-100 §6). Any administrator sees them; super admins change
 * them, and issue the single-use token that enrolls a shared sensor
 * (RFC-100 §7).
 */
export default function PlatformScanningPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = usePlatformSensorProof()
  const shared = useSharedSensorsSetting()
  const zones = useSharedSensorInternalZones()
  const anomaly = useSharedSensorAnomaly()
  const canEdit = adminCan(me.role, 'super_admin')
  const egress = useSharedSensorsEgress()

  return (
    <Main>
      <PageHeader title={t('admin.proof.pageTitle')} description={t('admin.proof.pageDesc')} />
      <div className="mt-5 space-y-5">
        {shared.error ? (
          <ErrorState
            title={t('admin.sharedSensors.errorTitle')}
            error={shared.error}
            onRetry={() => void shared.mutate()}
          />
        ) : shared.isLoading || !shared.data ? (
          <Skeleton className="h-56 w-full" />
        ) : (
          <SharedSensorsForm
            enabled={shared.data.enabled}
            newOrgs={shared.data.new_orgs}
            ready={shared.data.ready}
            canEdit={canEdit}
            onSave={async (enabled, newOrgs, reason, code) => {
              const s = shared.data
              if (!s) return
              await saveSharedSensorsSetting({
                enabled,
                new_orgs: newOrgs,
                version: s.version ?? 0,
                reason,
                totp_code: code,
              })
              await shared.mutate()
            }}
          />
        )}
        <SharedSensorEnrollCard
          canEdit={adminCan(me.role, 'super_admin')}
          onIssue={({ name, ttlMinutes, reason, code }) =>
            createSharedSensorEnrollmentToken({
              name,
              ttl_minutes: ttlMinutes,
              reason,
              totp_code: code,
            })
          }
        />
        {egress.error ? (
          <ErrorState
            title={t('admin.sharedEgress.errorTitle')}
            error={egress.error}
            onRetry={() => void egress.mutate()}
          />
        ) : egress.isLoading || !egress.data ? (
          <Skeleton className="h-40 w-full" />
        ) : (
          <SharedSensorsEgressForm
            global={egress.data.global}
            regions={egress.data.regions}
            canEdit={adminCan(me.role, 'super_admin')}
            onSave={async (global, regions, reason, code) => {
              const e = egress.data
              if (!e) return
              await saveSharedSensorsEgress({
                global,
                regions,
                version: e.version ?? 0,
                reason,
                totp_code: code,
              })
              await egress.mutate()
            }}
          />
        )}
        {error ? (
          <ErrorState
            title={t('admin.proof.errorTitle')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-56 w-full" />
        ) : (
          <PlatformSensorProofForm
            required={data.required}
            stored={(data.version ?? 0) > 0}
            defaultValue={data.default}
            canEdit={canEdit}
            onSave={async (required, reason, code) => {
              await savePlatformSensorProof({
                required,
                version: data.version ?? 0,
                reason,
                totp_code: code,
              })
              await mutate()
            }}
          />
        )}
        {zones.error ? (
          <ErrorState
            title={t('admin.internalZones.errorTitle')}
            error={zones.error}
            onRetry={() => void zones.mutate()}
          />
        ) : zones.isLoading || !zones.data ? (
          <Skeleton className="h-56 w-full" />
        ) : (
          <PlatformSensorProofForm
            prefix="admin.internalZones"
            required={zones.data.allowed}
            stored={(zones.data.version ?? 0) > 0}
            defaultValue={zones.data.default}
            enforced={zones.data.enforced}
            canEdit={canEdit}
            onSave={async (allowed, reason, code) => {
              const z = zones.data
              if (!z) return
              await saveSharedSensorInternalZones({
                allowed,
                version: z.version ?? 0,
                reason,
                totp_code: code,
              })
              await zones.mutate()
            }}
          />
        )}
        {anomaly.error ? (
          <ErrorState
            title={t('admin.anomaly.errorTitle')}
            error={anomaly.error}
            onRetry={() => void anomaly.mutate()}
          />
        ) : anomaly.isLoading || !anomaly.data ? (
          <Skeleton className="h-56 w-full" />
        ) : (
          <SharedSensorAnomalyForm
            thresholds={{
              distinct_domains_per_day: anomaly.data.distinct_domains_per_day,
              failures_per_day: anomaly.data.failures_per_day,
              deny_list_hits_per_day: anomaly.data.deny_list_hits_per_day,
            }}
            canEdit={canEdit}
            onSave={async (next, reason, code) => {
              const a = anomaly.data
              if (!a) return
              await saveSharedSensorAnomaly({
                ...next,
                version: a.version ?? 0,
                reason,
                totp_code: code,
              })
              await anomaly.mutate()
            }}
          />
        )}
      </div>
    </Main>
  )
}
