'use client'

import { useState } from 'react'
import { Waypoints } from 'lucide-react'
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
import { DetailDisclosure, DetailSection } from '@/features/shared'
import { Permission, useHasPermission } from '@/lib/permissions'

import {
  invalidateProxyPools,
  setProxyAssignment,
  useProxyAssignments,
  useProxyPools,
} from '../api/use-proxy-pools'
import { describeProxyError } from '../lib/errors'
import type { SetProxyAssignmentRequest } from '../types'

const POOL_PREFIX = 'pool:'

/** The select value for a request, and back. */
export function pathValue(mode?: string, poolId?: string | null): string {
  if (mode === 'direct') return 'direct'
  if (mode === 'pool' && poolId) return `${POOL_PREFIX}${poolId}`
  return 'inherit'
}

export function pathRequest(value: string): SetProxyAssignmentRequest {
  if (value === 'direct') return { mode: 'direct' }
  if (value.startsWith(POOL_PREFIX))
    return { mode: 'pool', pool_id: value.slice(POOL_PREFIX.length) }
  return { mode: 'inherit' }
}

/**
 * Sensor detail: the sensor's network path. Hidden without
 * sensors:egress:read; changing it needs sensors:egress:write. Not offered
 * for shared sensors, which never use an organization's proxies.
 */
export function SensorNetworkPathSection({ sensorId }: { sensorId: string }) {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.SensorEgressRead)
  const canWrite = useHasPermission(Permission.SensorEgressWrite)
  const pools = useProxyPools(canRead)
  const assignments = useProxyAssignments(canRead)
  const [saving, setSaving] = useState(false)
  const [confirmDirect, setConfirmDirect] = useState(false)
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
                      : t('proxyPools.sensor.poolDisabled', '{name} (disabled)', { name: p.name })}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </>
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
              "A pool chosen here carries all of this sensor's scan traffic. The organization default only carries public targets. A sensor needs a recent version with network confinement to run proxied scans: without it, the sensor receives no scan jobs while a pool applies to it. It never falls back to a direct connection."
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
    </DetailSection>
  )
}
