'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Lock, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import {
  DataTable,
  Meter,
  StackedCell,
  TonePill,
  type MeterTone,
  type PillTone,
} from '@/features/shared'
import { agoShort, exactTime } from '@/features/sensors/lib/format'
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

/**
 * A pool's proxies with their health, in the shared data table (cards on a
 * phone). Credentials are never shown: a lock says a proxy has them and when
 * they last changed, so an old secret is easy to spot for rotation.
 */
export function EndpointTable({ poolId, endpoints, canWrite }: EndpointTableProps) {
  const { t } = useTranslation()
  const now = useNow()
  const [busy, setBusy] = useState<string | null>(null)

  const columns = useMemo<ColumnDef<ProxyEndpoint>[]>(() => {
    async function patch(e: ProxyEndpoint, body: { enabled?: boolean; reset_health?: boolean }) {
      setBusy(e.id)
      try {
        await updateProxyEndpoint(poolId, e.id, body)
        await invalidateProxyPools()
      } catch (err) {
        toast.error(
          describeProxyError(
            err,
            t,
            t('proxyPools.toast.updateFailed', 'Could not update the proxy')
          )
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

    const cols: ColumnDef<ProxyEndpoint>[] = [
      {
        id: 'proxy',
        meta: { label: t('proxyPools.col.proxy', 'Proxy') },
        header: t('proxyPools.col.proxy', 'Proxy'),
        cell: ({ row: { original: e } }) => (
          <StackedCell
            primary={<span className="break-words">{e.label || endpointUrl(e)}</span>}
            secondary={
              <span className="flex items-center gap-1.5 font-mono text-xs">
                {e.label && <span className="break-all">{endpointUrl(e)}</span>}
                {e.has_credentials && (
                  <Lock
                    role="img"
                    className="size-3.5 shrink-0 text-muted-foreground"
                    aria-label={
                      e.credentials_updated_at
                        ? t(
                            'proxyPools.hasCredentialsSince',
                            'Has credentials (stored encrypted), changed {ago}',
                            { ago: agoShort(e.credentials_updated_at, now, t) }
                          )
                        : t('proxyPools.hasCredentials', 'Has credentials (stored encrypted)')
                    }
                    data-testid="proxy-lock"
                  />
                )}
              </span>
            }
          />
        ),
      },
      {
        id: 'state',
        meta: { label: t('proxyPools.col.state', 'State') },
        header: t('proxyPools.col.state', 'State'),
        cell: ({ row: { original: e } }) => {
          const h = e.health
          return (
            <div className="min-w-0 space-y-1">
              <TonePill
                tone={e.enabled ? STATE_TONE[h.state] : 'muted'}
                label={e.enabled ? stateLabel(h.state) : t('proxyPools.state.disabled', 'Disabled')}
                state={e.enabled ? h.state : 'disabled'}
                detail={
                  e.enabled && h.state === 'quarantined' && h.quarantined_until
                    ? t('proxyPools.quarantinedUntil', 'until {time}', {
                        time: exactTime(h.quarantined_until) ?? '',
                      })
                    : undefined
                }
              />
              {h.last_error && (
                <p
                  className="max-w-[18rem] break-words text-xs text-muted-foreground"
                  data-testid="proxy-last-error"
                >
                  {h.last_error}
                </p>
              )}
            </div>
          )
        },
      },
      {
        id: 'score',
        meta: { label: t('proxyPools.col.score', 'Score') },
        header: t('proxyPools.col.score', 'Score'),
        cell: ({ row: { original: e } }) => {
          const pct = scorePercent(e.health.score)
          return (
            <div className="w-28">
              <Meter
                value={pct}
                max={100}
                tone={SCORE_TONE[e.health.state]}
                label={t('proxyPools.scoreLabel', 'Health score {pct}%', { pct })}
              />
              <span className="text-xs tabular-nums text-muted-foreground">{pct}%</span>
            </div>
          )
        },
      },
      {
        id: 'handshake',
        meta: { label: t('proxyPools.col.handshake', 'Connect time (p95)') },
        header: t('proxyPools.col.handshake', 'Connect time (p95)'),
        cell: ({ row: { original: e } }) => (
          <span className="tabular-nums">
            {e.health.handshake_ms_p95 != null && e.health.ok_total > 0
              ? t('proxyPools.ms', '{ms} ms', { ms: e.health.handshake_ms_p95 })
              : '—'}
          </span>
        ),
      },
      {
        id: 'connections',
        meta: { label: t('proxyPools.col.connections', 'Connections') },
        header: t('proxyPools.col.connections', 'Connections'),
        cell: ({ row: { original: e } }) => (
          <span className="tabular-nums" data-testid="proxy-connections">
            {t('proxyPools.connections', '{ok} ok, {fail} failed', {
              ok: e.health.ok_total.toLocaleString(),
              fail: e.health.fail_total.toLocaleString(),
            })}
          </span>
        ),
      },
      {
        id: 'last_ok',
        meta: { label: t('proxyPools.col.lastOk', 'Last OK') },
        header: t('proxyPools.col.lastOk', 'Last OK'),
        cell: ({ row: { original: e } }) => (
          <span className="text-muted-foreground" title={exactTime(e.health.last_ok_at)}>
            {e.health.last_ok_at ? agoShort(e.health.last_ok_at, now, t) : '—'}
          </span>
        ),
      },
      {
        id: 'actions',
        header: () => <span className="sr-only">{t('proxyPools.col.actions', 'Actions')}</span>,
        cell: ({ row: { original: e } }) => (
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
                aria-label={t('proxyPools.resetHealthNamed', 'Reset health of {name}', {
                  name: e.label || endpointUrl(e),
                })}
              >
                <RotateCcw className="size-4" aria-hidden />
                <span className="max-sm:sr-only">
                  {t('proxyPools.resetHealth', 'Reset health')}
                </span>
              </Button>
            )}
          </div>
        ),
      },
    ]
    return cols
  }, [t, now, busy, canWrite, poolId])

  return (
    <div data-testid="proxy-endpoint-table">
      <DataTable
        columns={columns}
        data={endpoints}
        getRowId={(e) => e.id}
        showSearch={false}
        showColumnToggle={false}
        showPagination={endpoints.length > 20}
        pageSize={20}
      />
    </div>
  )
}
