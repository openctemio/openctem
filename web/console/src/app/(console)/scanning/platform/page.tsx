'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader } from '@/features/shared'
import { Info } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useUrlFilter } from '@/hooks/use-url-param'
import {
  SharedFleetPanel,
  SharedQueuePanel,
} from '@console/features/admin-console/components/shared-fleet-panels'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
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
} from '@console/features/admin-console/api/use-scan-policy'
import { PlatformSensorProofForm } from '@console/features/admin-console/components/platform-sensor-proof-form'
import { SharedSensorAnomalyForm } from '@console/features/admin-console/components/shared-sensor-anomaly-form'
import { InstanceScanZonesCard } from '@console/features/admin-console/components/instance-scan-zones-card'
import { useInstanceScanZones } from '@console/features/admin-console/api/use-instance-scan-zones'
import { SharedSensorEnrollCard } from '@console/features/admin-console/components/shared-sensor-enroll-card'
import { SharedSensorsForm } from '@console/features/admin-console/components/shared-sensors-form'
import { SharedSensorsEgressForm } from '@console/features/admin-console/components/shared-sensors-egress-form'
import { adminCan } from '@console/features/admin-console/types'

/**
 * Scanning > Platform scanning: everything an instance administrator sets for
 * the platform's own and shared sensors, in one page. Policy: whether platform
 * sensors need a verified domain before they scan a target (RFC-054 §8.1) and
 * whether shared sensors may scan internal zones (RFC-100 §6.1). Fleet: the
 * instance switch, the sensors and the single-use enrollment token (RFC-100
 * §5, §7). Queue: lanes, per-organization use and job metadata (§12). Zones,
 * Egress (§9) and Anomalies (§9) follow. Until a value is stored the
 * deployment default applies (MANAGED_SERVICE changes the defaults, RFC-100
 * §6). Any administrator sees them; super admins change them. While shared
 * sensors are not available in the release (the API reports ready=false), the
 * page shows one notice and the domain-proof policy only.
 */

const TABS = ['policy', 'fleet', 'queue', 'zones', 'egress', 'anomalies'] as const

function useScanning() {
  const me = useAdmin()
  return {
    canEdit: adminCan(me.role, 'super_admin'),
    proof: usePlatformSensorProof(),
    shared: useSharedSensorsSetting(),
    zones: useSharedSensorInternalZones(),
    anomaly: useSharedSensorAnomaly(),
    instanceZones: useInstanceScanZones(),
    egress: useSharedSensorsEgress(),
  }
}

type Scanning = ReturnType<typeof useScanning>

function ProofPolicy({ s }: { s: Scanning }) {
  const { t } = useTranslation()
  const {
    proof: { data, error, isLoading, mutate },
    canEdit,
  } = s
  return error ? (
    <ErrorState title={t('admin.proof.errorTitle')} error={error} onRetry={() => void mutate()} />
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
  )
}

function NotAvailablePanel() {
  const { t } = useTranslation()
  return (
    <Card data-testid="shared-sensors-unavailable">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Info className="size-4 text-muted-foreground" aria-hidden />
          {t(
            'admin.scanning.unavailable.title',
            'Shared sensors are not available in this release'
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">
        {t(
          'admin.scanning.unavailable.body',
          'The fleet, queue, zones, egress addresses and alert thresholds of shared sensors appear here once the release enables them. The domain-proof policy below applies to the platform sensors today.'
        )}
      </CardContent>
    </Card>
  )
}

function SharedTabs({ s }: { s: Scanning }) {
  const { t } = useTranslation()
  const [rawTab, setTab] = useUrlFilter('tab', 'policy')
  const tab = (TABS as readonly string[]).includes(rawTab) ? rawTab : 'policy'
  const { shared, zones, anomaly, instanceZones, egress, canEdit } = s
  return (
    <Tabs value={tab} onValueChange={setTab}>
      <TabsList className="h-auto flex-wrap justify-start">
        <TabsTrigger value="policy">{t('admin.scanning.tab.policy', 'Policy')}</TabsTrigger>
        <TabsTrigger value="fleet">{t('admin.scanning.tab.fleet', 'Fleet')}</TabsTrigger>
        <TabsTrigger value="queue">{t('admin.scanning.tab.queue', 'Queue')}</TabsTrigger>
        <TabsTrigger value="zones">{t('admin.scanning.tab.zones', 'Zones')}</TabsTrigger>
        <TabsTrigger value="egress">{t('admin.scanning.tab.egress', 'Egress')}</TabsTrigger>
        <TabsTrigger value="anomalies">
          {t('admin.scanning.tab.anomalies', 'Anomalies')}
        </TabsTrigger>
      </TabsList>
      <TabsContent value="policy" className="mt-5 space-y-5">
        <ProofPolicy s={s} />
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
      </TabsContent>
      <TabsContent value="fleet" className="mt-5 space-y-5">
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
      </TabsContent>
      <TabsContent value="queue" className="mt-5 space-y-5">
        <SharedQueuePanel />
      </TabsContent>
      <TabsContent value="zones" className="mt-5 space-y-5">
        {instanceZones.error ? (
          <ErrorState
            title={t('admin.instanceZones.errorTitle')}
            error={instanceZones.error}
            onRetry={() => void instanceZones.mutate()}
          />
        ) : instanceZones.isLoading || !instanceZones.data ? (
          <Skeleton className="h-40 w-full" />
        ) : (
          <InstanceScanZonesCard
            zones={instanceZones.data.items ?? []}
            canEdit={canEdit}
            onChanged={() => instanceZones.mutate()}
          />
        )}
      </TabsContent>
      <TabsContent value="egress" className="mt-5 space-y-5">
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
            canEdit={canEdit}
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
      </TabsContent>
      <TabsContent value="anomalies" className="mt-5 space-y-5">
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
      </TabsContent>
    </Tabs>
  )
}

export default function PlatformScanningPage() {
  const { t } = useTranslation()
  const s = useScanning()
  const notAvailable = !!s.shared.data && !s.shared.data.ready
  return (
    <Main>
      <PageHeader
        title={t('admin.proof.pageTitle')}
        description={t(
          'admin.scanning.pageDesc',
          'Rules for the scans that run on the platform sensors and, when enabled, the shared sensor fleet.'
        )}
      />
      <div className="mt-5 space-y-5">
        {notAvailable ? (
          <>
            <NotAvailablePanel />
            <ProofPolicy s={s} />
          </>
        ) : (
          <SharedTabs s={s} />
        )}
      </div>
    </Main>
  )
}
