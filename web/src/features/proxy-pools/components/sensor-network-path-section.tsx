'use client'

import { useState } from 'react'
import { Waypoints } from 'lucide-react'
import { toast } from 'sonner'

import { useTranslation } from '@/context/i18n-provider'
import { DetailSection } from '@/features/shared'
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
  if (!canRead) return null

  const row = assignments.data?.items.find((a) => a.sensor_id === sensorId)
  const value = pathValue(row?.mode, row?.pool_id)
  const list = pools.data?.items ?? []
  // A pool the list no longer holds would show a blank select.
  const known =
    value === 'inherit' || value === 'direct' || list.some((p) => `${POOL_PREFIX}${p.id}` === value)

  async function change(next: string) {
    setSaving(true)
    try {
      await setProxyAssignment(sensorId, pathRequest(next))
      await invalidateProxyPools()
      toast.success(t('proxyPools.sensor.saved', 'Network path saved'))
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

  return (
    <DetailSection title={t('proxyPools.sensor.title', 'Network path')} icon={Waypoints}>
      <div className="space-y-2">
        <label htmlFor="sensor-network-path" className="sr-only">
          {t('proxyPools.sensor.title', 'Network path')}
        </label>
        <select
          id="sensor-network-path"
          value={known ? value : 'inherit'}
          disabled={!canWrite || saving || assignments.isLoading}
          onChange={(e) => void change(e.target.value)}
          className="border-input bg-background h-9 w-full rounded-md border px-3 text-sm"
        >
          <option value="inherit">
            {t('proxyPools.sensor.inherit', 'Inherit (organization default)')}
          </option>
          <option value="direct">{t('proxyPools.sensor.direct', 'Direct')}</option>
          {list.map((p) => (
            <option key={p.id} value={`${POOL_PREFIX}${p.id}`}>
              {p.name}
            </option>
          ))}
        </select>
        <p className="text-xs text-muted-foreground">
          <span>
            {t(
              'proxyPools.sensor.help',
              "A pool chosen here carries all of this sensor's scan traffic. The organization default only carries public targets. A sensor needs a recent version with network confinement to run proxied scans: without it, the sensor receives no scan jobs while a pool applies to it. It never falls back to a direct connection."
            )}
          </span>
        </p>
      </div>
    </DetailSection>
  )
}
