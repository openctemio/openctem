'use client'

import { useState } from 'react'
import { Lock, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { TonePill, Meter, type PillTone, type MeterTone } from '@/features/shared'
import { exactTime, agoShort } from '@/features/sensors/lib/format'
import { useNow } from '@/hooks/use-now'

import { invalidateProxyPools, updateProxyEndpoint } from '../api/use-proxy-pools'
import { describeProxyError } from '../lib/errors'
import { endpointUrl, scorePercent } from '../lib/mask'
import type { ProxyEndpoint, ProxyHealthState } from '../types'

const STATE_TONE: Record<ProxyHealthState, PillTone> = {
  healthy: 'success',
  probation: 'warning',
  quarantined: 'destructive',
}
const SCORE_TONE: Record<ProxyHealthState, MeterTone> = {
  healthy: 'success',
  probation: 'warning',
  quarantined: 'destructive',
}

interface EndpointTableProps {
  poolId: string
  endpoints: ProxyEndpoint[]
  canWrite: boolean
}

/** A pool's endpoints with their health. Credentials are never shown, only a lock. */
export function EndpointTable({ poolId, endpoints, canWrite }: EndpointTableProps) {
  const { t } = useTranslation()
  const now = useNow()
  const [busy, setBusy] = useState<string | null>(null)

  async function patch(e: ProxyEndpoint, body: { enabled?: boolean; reset_health?: boolean }) {
    setBusy(e.id)
    try {
      await updateProxyEndpoint(poolId, e.id, body)
      await invalidateProxyPools()
      toast.success(
        body.reset_health
          ? t('proxyPools.toast.healthReset', 'Health reset')
          : t('proxyPools.toast.endpointUpdated', 'Proxy updated')
      )
    } catch (err) {
      toast.error(
        describeProxyError(err, t, t('proxyPools.toast.updateFailed', 'Could not update the proxy'))
      )
    } finally {
      setBusy(null)
    }
  }

  const stateLabel = (s: ProxyHealthState) =>
    s === 'healthy'
      ? t('proxyPools.state.healthy', 'Healthy')
      : s === 'probation'
        ? t('proxyPools.state.probation', 'Probation')
        : t('proxyPools.state.quarantined', 'Quarantined')

  return (
    <div className="overflow-x-auto" data-testid="proxy-endpoint-table">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b text-left text-xs text-muted-foreground">
            <th className="py-2 pr-3 font-medium">{t('proxyPools.col.label', 'Label')}</th>
            <th className="py-2 pr-3 font-medium">{t('proxyPools.col.endpoint', 'Endpoint')}</th>
            <th className="py-2 pr-3 font-medium">{t('proxyPools.col.state', 'State')}</th>
            <th className="py-2 pr-3 font-medium">{t('proxyPools.col.score', 'Score')}</th>
            <th className="py-2 pr-3 font-medium">{t('proxyPools.col.lastError', 'Last error')}</th>
            <th className="py-2 pr-3 font-medium">{t('proxyPools.col.lastOk', 'Last OK')}</th>
            <th className="py-2 text-right font-medium">
              {t('proxyPools.col.actions', 'Actions')}
            </th>
          </tr>
        </thead>
        <tbody>
          {endpoints.map((e) => {
            const h = e.health
            const pct = scorePercent(h.score)
            return (
              <tr
                key={e.id}
                className="border-b last:border-0 align-top"
                data-testid="proxy-endpoint-row"
              >
                <td className="py-2 pr-3">
                  <span className="break-words">{e.label || '—'}</span>
                </td>
                <td className="py-2 pr-3">
                  <span className="flex items-center gap-1.5 font-mono text-xs">
                    <span className="break-all">{endpointUrl(e)}</span>
                    {e.has_credentials && (
                      <Lock
                        className="size-3.5 shrink-0 text-muted-foreground"
                        aria-label={t(
                          'proxyPools.hasCredentials',
                          'Has credentials (stored encrypted)'
                        )}
                        data-testid="proxy-lock"
                      />
                    )}
                  </span>
                </td>
                <td className="py-2 pr-3">
                  <TonePill
                    tone={e.enabled ? STATE_TONE[h.state] : 'muted'}
                    label={
                      e.enabled ? stateLabel(h.state) : t('proxyPools.state.disabled', 'Disabled')
                    }
                    state={e.enabled ? h.state : 'disabled'}
                    detail={
                      h.state === 'quarantined' && h.quarantined_until
                        ? t('proxyPools.quarantinedUntil', 'until {time}', {
                            time: exactTime(h.quarantined_until) ?? '',
                          })
                        : undefined
                    }
                  />
                </td>
                <td className="w-32 py-2 pr-3">
                  <Meter
                    value={pct}
                    max={100}
                    tone={SCORE_TONE[h.state]}
                    label={t('proxyPools.scoreLabel', 'Health score {pct}%', { pct })}
                  />
                  <span className="text-xs text-muted-foreground">{pct}%</span>
                </td>
                <td className="max-w-[16rem] py-2 pr-3">
                  <span className="break-words text-xs text-muted-foreground">
                    {h.last_error || '—'}
                  </span>
                </td>
                <td className="py-2 pr-3">
                  <span className="text-xs text-muted-foreground" title={exactTime(h.last_ok_at)}>
                    {h.last_ok_at ? agoShort(h.last_ok_at, now, t) : '—'}
                  </span>
                </td>
                <td className="py-2">
                  <div className="flex items-center justify-end gap-2">
                    <Switch
                      checked={e.enabled}
                      disabled={!canWrite || busy === e.id}
                      onCheckedChange={(enabled) => void patch(e, { enabled })}
                      aria-label={t('proxyPools.enableNamed', 'Enable {name}', {
                        name: e.label || endpointUrl(e),
                      })}
                    />
                    {canWrite && (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={busy === e.id}
                        onClick={() => void patch(e, { reset_health: true })}
                      >
                        <RotateCcw className="size-4" aria-hidden />
                        {t('proxyPools.resetHealth', 'Reset health')}
                      </Button>
                    )}
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
