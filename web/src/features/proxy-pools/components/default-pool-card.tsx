'use client'

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { ReadOnlyNotice } from '@/features/shared'
import { useAllSensors } from '@/lib/api/sensor-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'

import {
  createProxyPool,
  invalidateProxyPools,
  saveProxyEndpoints,
  updateProxyPool,
  useProxyAssignments,
  useProxyPools,
} from '../api/use-proxy-pools'
import { describeProxyError, isInvalidEndpointError } from '../lib/errors'
import { hasNoProxyLines } from '../lib/endpoints-text'
import { defaultPoolImpacts } from '../lib/impact'
import { maskPasteText } from '../lib/mask'
import type { ProxyPool } from '../types'
import { EndpointTable } from './endpoint-table'
import { ImpactList } from './impact-list'
import { PasteListField } from './paste-list-field'
import { TestPoolButton } from './test-pool-button'

interface DefaultPoolCardProps {
  /** The pool with is_default, if the organization has one. */
  pool: ProxyPool | undefined
  canWrite: boolean
}

/**
 * Use proxies for scans: the organization default pool. It applies to public
 * targets only. Turning it on with no proxies would make every scan fail
 * closed, so it needs at least one line.
 */
export function DefaultPoolCard({ pool, canWrite }: DefaultPoolCardProps) {
  const { t } = useTranslation()
  const stored = maskPasteText(pool?.endpoints_text ?? '')
  const [text, setText] = useState(stored)
  const [enabled, setEnabled] = useState(pool?.enabled ?? false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Which sensors the default pool would hold back, from what they report.
  // Needs the fleet (sensors:read); without it there is no preview.
  const canReadSensors = useHasPermission(Permission.SensorsRead)
  const allPools = useProxyPools()
  const assignments = useProxyAssignments()
  const fleet = useAllSensors(undefined, canReadSensors && enabled)
  const impacts =
    enabled && fleet.data && assignments.data
      ? defaultPoolImpacts(
          fleet.data.items ?? [],
          assignments.data.items,
          allPools.data?.items ?? []
        )
      : []

  // Follow the server after a save or a refresh.
  useEffect(() => {
    setText(stored)
    setEnabled(pool?.enabled ?? false)
  }, [stored, pool?.enabled, pool?.revision])

  const dirty = text !== stored || enabled !== (pool?.enabled ?? false)
  const noLines = hasNoProxyLines(text)
  const needLines = enabled && noLines

  async function save() {
    if (needLines) {
      setError(
        t(
          'proxyPools.default.needsProxy',
          'Add at least one proxy before turning proxies on: scans fail closed when the pool has none.'
        )
      )
      return
    }
    setSaving(true)
    setError(null)
    try {
      if (!pool) {
        await createProxyPool({
          name: t('proxyPools.default.name', 'Organization default'),
          is_default: true,
          enabled,
          endpoints_text: text,
        })
      } else {
        // The API refuses an enabled pool without a proxy: turn the pool off
        // before emptying its list, and fill the list before turning it on.
        const turningOff = pool.enabled && !enabled
        if (turningOff) await updateProxyPool(pool.id, { enabled })
        if (text !== stored) await saveProxyEndpoints(pool.id, text)
        if (!turningOff && enabled !== pool.enabled) await updateProxyPool(pool.id, { enabled })
      }
      await invalidateProxyPools()
      toast.success(t('proxyPools.toast.saved', 'Proxies saved'))
    } catch (e) {
      const msg = describeProxyError(
        e,
        t,
        t('proxyPools.toast.saveFailed', 'Could not save the proxies')
      )
      if (isInvalidEndpointError(e)) setError(msg)
      else toast.error(msg)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card data-testid="default-pool-card">
      <CardHeader>
        <CardTitle className="text-base">
          {t('proxyPools.default.title', 'Use proxies for scans')}
        </CardTitle>
        <CardDescription>
          {t(
            'proxyPools.default.description',
            'Your own sensors send scans to public targets through these proxies. Private addresses are still scanned directly. A sensor can use another pool or go direct on its page. Shared sensors never use your proxies.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!canWrite && (
          <ReadOnlyNotice
            reason={t(
              'proxyPools.readOnly',
              'You can view proxies but not change them: that needs the sensors:egress:write permission.'
            )}
          />
        )}
        <div className="flex items-center gap-3">
          <Switch
            id="proxy-default-enabled"
            checked={enabled}
            onCheckedChange={setEnabled}
            disabled={!canWrite || saving}
          />
          <Label htmlFor="proxy-default-enabled">
            {t('proxyPools.default.toggle', 'Use proxies for scans')}
          </Label>
        </div>
        <ImpactList impacts={impacts} pending={!pool?.enabled} />
        <PasteListField value={text} onChange={setText} readOnly={!canWrite} error={error} />
        {canWrite && (
          <div className="flex justify-end">
            <Button onClick={() => void save()} disabled={saving || !dirty}>
              {saving && <Loader2 className="size-4 animate-spin" aria-hidden />}
              {t('proxyPools.save', 'Save')}
            </Button>
          </div>
        )}
        {pool && pool.endpoints.length > 0 && (
          <>
            <div className="flex justify-end">
              <TestPoolButton pool={pool} canWrite={canWrite} />
            </div>
            <EndpointTable poolId={pool.id} endpoints={pool.endpoints} canWrite={canWrite} />
          </>
        )}
      </CardContent>
    </Card>
  )
}
