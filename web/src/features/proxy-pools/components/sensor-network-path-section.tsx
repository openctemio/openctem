'use client'

import { useState } from 'react'
import { AlertTriangle, Info, Waypoints } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { DetailCallout, DetailDisclosure, DetailSection } from '@/features/shared'
import { Permission, useHasPermission } from '@/lib/permissions'

import {
  invalidateProxyPools,
  setProxyAssignment,
  useProxyAssignments,
  useProxyPools,
} from '../api/use-proxy-pools'
import { describeProxyError } from '../lib/errors'
import {
  POOL_PREFIX,
  pathRequest,
  pathValue,
  pathWarning,
  type PathWarning,
} from '../lib/path-warning'

export { pathRequest, pathValue, pathWarning, type PathWarning }

/**
 * Sensor detail: the sensor's network path. Hidden without
 * sensors:egress:read; changing it needs sensors:egress:write. Not offered
 * for shared sensors, which never use an organization's proxies.
 */
export function SensorNetworkPathSection({
  sensorId,
  capabilities,
}: {
  sensorId: string
  /** What the sensor last reported (null: never reported). */
  capabilities?: string[] | null
}) {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.SensorEgressRead)
  const canWrite = useHasPermission(Permission.SensorEgressWrite)
  const pools = useProxyPools(canRead)
  const assignments = useProxyAssignments(canRead)
  const [saving, setSaving] = useState(false)
  const [confirmDirect, setConfirmDirect] = useState(false)
  // A pool choice that would leave this sensor without jobs, asked first.
  const [confirmPool, setConfirmPool] = useState<string | null>(null)
  if (!canRead) return null

  const failed = !!pools.error || !!assignments.error
  const loading = !failed && (!pools.data || !assignments.data)
  const row = assignments.data?.items.find((a) => a.sensor_id === sensorId)
  const value = pathValue(row?.mode, row?.pool_id)
  const list = pools.data?.items ?? []
  // A pool the list no longer holds would show a blank select.
  const known =
    value === 'inherit' || value === 'direct' || list.some((p) => `${POOL_PREFIX}${p.id}` === value)
  const defaultOn = list.some((p) => p.is_default && p.enabled)
  const warning =
    loading || failed ? null : pathWarning(known ? value : 'inherit', list, capabilities)

  async function change(next: string) {
    setSaving(true)
    try {
      await setProxyAssignment(sensorId, pathRequest(next))
      await invalidateProxyPools()
    } catch (e) {
      toast.error(
        describeProxyError(
          e,
          t,
          t('proxyPools.sensor.saveFailed', 'Could not save the network path')
        )
      )
    } finally {
      setSaving(false)
    }
  }

  function choose(next: string) {
    // Direct sends this sensor's scans from its own address, around the
    // organization's proxies: ask first while they are on.
    if (next === 'direct' && defaultOn) setConfirmDirect(true)
    else if (pathWarning(next, list, capabilities) === 'unsupported') setConfirmPool(next)
    else void change(next)
  }

  return (
    <DetailSection title={t('proxyPools.sensor.title', 'Network path')} icon={Waypoints}>
      <div className="space-y-2">
        {failed ? (
          <div className="flex flex-wrap items-center gap-2" role="alert">
            <p className="text-sm text-destructive">
              {t('proxyPools.sensor.loadFailed', 'Could not load the network path.')}
            </p>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                void pools.mutate()
                void assignments.mutate()
              }}
            >
              {t('common.retry', 'Retry')}
            </Button>
          </div>
        ) : loading ? (
          <Skeleton className="h-9 w-full" data-testid="network-path-skeleton" />
        ) : (
          <>
            <label htmlFor="sensor-network-path" className="sr-only">
              {t('proxyPools.sensor.title', 'Network path')}
            </label>
            <Select
              value={known ? value : 'inherit'}
              disabled={!canWrite || saving}
              onValueChange={choose}
            >
              <SelectTrigger id="sensor-network-path" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="inherit">
                  {t('proxyPools.sensor.inherit', 'Inherit (organization default)')}
                </SelectItem>
                <SelectItem value="direct">{t('proxyPools.sensor.direct', 'Direct')}</SelectItem>
                {list.map((p) => (
                  <SelectItem key={p.id} value={`${POOL_PREFIX}${p.id}`}>
                    {p.enabled
                      ? p.name
                      : t('proxyPools.sensor.poolDisabled', '{name} (disabled, scans fail)', {
                          name: p.name,
                        })}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </>
        )}
        {warning === 'pool-disabled' && (
          <DetailCallout
            tone="warning"
            icon={AlertTriangle}
            title={t('proxyPools.sensor.warnDisabledTitle', 'The chosen pool is disabled')}
          >
            {t(
              'proxyPools.sensor.warnDisabledBody',
              "This sensor's scans fail until you enable the pool or choose another path. They never go direct."
            )}
          </DetailCallout>
        )}
        {warning === 'unsupported' && (
          <DetailCallout
            tone="warning"
            icon={AlertTriangle}
            title={t('proxyPools.sensor.warnUnsupportedTitle', 'This sensor receives no scan jobs')}
          >
            {t(
              'proxyPools.sensor.warnUnsupportedBody',
              'A proxy pool applies to it and it does not report proxy support. Upgrade it and run it with network confinement, or choose Direct.'
            )}
          </DetailCallout>
        )}
        {warning === 'validate-waits' && (
          <DetailCallout
            tone="info"
            icon={Info}
            title={t('proxyPools.sensor.warnValidateTitle', 'Validation jobs wait')}
          >
            {t(
              'proxyPools.sensor.warnValidateBody',
              "This sensor's version does not send validation probes through the proxy pool, so it receives no validation jobs while a pool applies. Scans run through the pool."
            )}
          </DetailCallout>
        )}
        <p className="text-xs text-muted-foreground">
          {t('proxyPools.sensor.summary', "The proxy pool that carries this sensor's scans.")}
        </p>
        <DetailDisclosure
          summary={t('proxyPools.sensor.howItWorks', 'How network paths work')}
          className="text-xs"
        >
          <p className="mt-1 text-muted-foreground">
            {t(
              'proxyPools.sensor.help',
              "A pool chosen here carries all of this sensor's scan and validation traffic. The organization default only carries public targets. A sensor without proxy support (a recent version with network confinement) receives no scan or validation jobs while a pool applies to it. Traffic never falls back to a direct connection: while the chosen pool is disabled, this sensor's scans fail."
            )}
          </p>
        </DetailDisclosure>
      </div>
      <ConfirmDialog
        open={confirmDirect}
        onOpenChange={setConfirmDirect}
        destructive
        title={t('proxyPools.sensor.directTitle', 'Send this sensor direct?')}
        desc={t(
          'proxyPools.sensor.directDesc',
          "The organization's proxies are on. A direct sensor sends its scan traffic from its own address, around them."
        )}
        confirmText={t('proxyPools.sensor.directConfirm', 'Go direct')}
        handleConfirm={() => {
          setConfirmDirect(false)
          return change('direct')
        }}
      />
      <ConfirmDialog
        open={confirmPool !== null}
        onOpenChange={(open) => !open && setConfirmPool(null)}
        destructive
        title={t('proxyPools.sensor.poolTitle', 'This sensor would stop getting scan jobs')}
        desc={t(
          'proxyPools.sensor.poolDesc',
          'The sensor does not report proxy support, so a proxy pool cannot carry its scans and none are sent to it. Upgrade it and run it with network confinement, or choose Direct.'
        )}
        confirmText={t('proxyPools.sensor.poolConfirm', 'Use the pool anyway')}
        handleConfirm={() => {
          const next = confirmPool
          setConfirmPool(null)
          return next ? change(next) : undefined
        }}
      />
    </DetailSection>
  )
}
