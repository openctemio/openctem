'use client'

import { useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { TonePill } from '@/features/shared'
import { useSensors } from '@/lib/api/sensor-hooks'

import { startProxyPoolTest, useProxyPoolTestResults } from '../api/use-proxy-pool-test'
import { describeProxyError, isRateLimitedError } from '../lib/errors'
import {
  CLASS_TEXT,
  MAX_TEST_SENSORS,
  isFinished,
  testableSensors,
  toggleSensor,
  untestableCount,
} from '../lib/proxy-test'
import type { ProxyPool, ProxyTestEndpointResult, ProxyTestOutcome } from '../types'

interface TestPoolDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  pool: ProxyPool
}

/**
 * Test a pool: pick up to three online sensors, each connects through every
 * endpoint to the platform's echo and reports what it saw (handshake time,
 * exit address, IPv4 and IPv6, a proxy that only allows port 443). The
 * platform never connects to a proxy. A pool can be tested before it is
 * enabled or assigned.
 */
export function TestPoolDialog({ open, onOpenChange, pool }: TestPoolDialogProps) {
  const { t } = useTranslation()
  const sensors = useSensors({ per_page: 100 }, { isPaused: () => !open })
  const [selected, setSelected] = useState<string[]>([])
  const [starting, setStarting] = useState(false)
  const [commandIds, setCommandIds] = useState<string[]>([])
  const results = useProxyPoolTestResults(pool.id, commandIds)

  const all = sensors.data?.items ?? []
  const choices = testableSensors(all)
  const blocked = untestableCount(all)
  const outcomes = results.data?.items ?? []
  const running =
    commandIds.length > 0 && !(outcomes.length > 0 && outcomes.every((o) => isFinished(o.status)))

  async function run() {
    setStarting(true)
    try {
      const started = await startProxyPoolTest(pool.id, selected)
      setCommandIds(started.items.map((i) => i.command_id))
    } catch (e) {
      toast.error(
        isRateLimitedError(e)
          ? t(
              'proxyPools.test.rateLimited',
              'A pool can be tested once a minute. Try again shortly.'
            )
          : describeProxyError(e, t, t('proxyPools.test.startFailed', 'Could not start the test'))
      )
    } finally {
      setStarting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>
            {t('proxyPools.test.title', 'Test {name}', { name: pool.name })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'proxyPools.test.description',
              'The sensors you choose connect through each proxy and report what they saw. The platform never connects to your proxies, so a proxy on a private network can be tested by a sensor inside it.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          {commandIds.length === 0 ? (
            <fieldset className="space-y-2" data-testid="test-sensor-picker">
              <legend className="text-sm font-medium">
                {t('proxyPools.test.pick', 'Run the test from (up to {max} sensors)', {
                  max: MAX_TEST_SENSORS,
                })}
              </legend>
              {sensors.isLoading && !sensors.data ? (
                <Skeleton className="h-9 w-full" />
              ) : sensors.error ? (
                <p className="text-sm text-destructive" role="alert">
                  {t('proxyPools.test.sensorsFailed', 'Could not load the sensors.')}
                </p>
              ) : choices.length === 0 ? (
                <p className="text-sm text-muted-foreground" data-testid="test-no-sensor">
                  {t(
                    'proxyPools.test.noSensor',
                    'No sensor can run the test. It needs an online sensor of your organization that accepts platform proxy pools (an up to date version, not set to direct-only).'
                  )}
                </p>
              ) : (
                choices.map((s) => {
                  const checked = selected.includes(s.id)
                  const full = !checked && selected.length >= MAX_TEST_SENSORS
                  return (
                    <div key={s.id} className="flex items-center gap-2">
                      <Checkbox
                        id={`test-sensor-${s.id}`}
                        checked={checked}
                        disabled={full}
                        onCheckedChange={() => setSelected((cur) => toggleSensor(cur, s.id))}
                      />
                      <Label htmlFor={`test-sensor-${s.id}`} className="font-normal">
                        {s.name}
                      </Label>
                    </div>
                  )
                })
              )}
              {choices.length > 0 && blocked > 0 && (
                <p className="text-xs text-muted-foreground">
                  {t(
                    'proxyPools.test.blocked',
                    '{count} other sensors are offline or cannot test proxies.',
                    { count: blocked }
                  )}
                </p>
              )}
            </fieldset>
          ) : (
            <div className="space-y-4" data-testid="test-results">
              {outcomes.length === 0 ? (
                <Skeleton className="h-16 w-full" />
              ) : (
                outcomes.map((o) => <SensorOutcome key={o.command_id} outcome={o} />)
              )}
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            {t('common.close', 'Close')}
          </Button>
          {commandIds.length === 0 ? (
            <Button
              type="button"
              disabled={selected.length === 0 || starting}
              onClick={() => void run()}
            >
              {starting && <Loader2 className="size-4 animate-spin" aria-hidden />}
              {t('proxyPools.test.run', 'Run test')}
            </Button>
          ) : (
            <Button
              type="button"
              disabled={running}
              onClick={() => {
                setCommandIds([])
              }}
            >
              {t('proxyPools.test.again', 'Test again')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function SensorOutcome({ outcome }: { outcome: ProxyTestOutcome }) {
  const { t } = useTranslation()
  const done = isFinished(outcome.status)
  return (
    <section className="space-y-2" data-testid="test-outcome">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-medium break-words">{outcome.sensor_name}</h3>
        {outcome.status === 'failed' ||
        outcome.status === 'expired' ||
        outcome.status === 'canceled' ? (
          <TonePill
            tone="destructive"
            state={outcome.status}
            label={
              outcome.status === 'expired'
                ? t('proxyPools.test.expired', 'No answer in time')
                : outcome.status === 'canceled'
                  ? t('proxyPools.test.canceled', 'Canceled')
                  : t('proxyPools.test.failed', 'Test failed')
            }
          />
        ) : done ? (
          <TonePill tone="success" state="completed" label={t('proxyPools.test.done', 'Done')} />
        ) : (
          <TonePill
            tone="info"
            state={outcome.status}
            label={
              outcome.status === 'pending'
                ? t('proxyPools.test.waiting', 'Waiting for the sensor')
                : t('proxyPools.test.running', 'Testing')
            }
          />
        )}
      </div>
      {outcome.error && (
        <p className="text-xs text-muted-foreground break-words">{outcome.error}</p>
      )}
      {outcome.results.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-xs text-muted-foreground">
                <th className="py-2 pr-3 font-medium">
                  {t('proxyPools.col.endpoint', 'Endpoint')}
                </th>
                <th className="py-2 pr-3 font-medium">
                  {t('proxyPools.test.col.result', 'Result')}
                </th>
                <th className="py-2 pr-3 font-medium">
                  {t('proxyPools.test.col.latency', 'Time')}
                </th>
                <th className="py-2 pr-3 font-medium">
                  {t('proxyPools.test.col.exit', 'Exit address')}
                </th>
                <th className="py-2 font-medium">
                  {t('proxyPools.test.col.ports', 'Families and ports')}
                </th>
              </tr>
            </thead>
            <tbody>
              {outcome.results.map((r) => (
                <ResultRow key={r.endpoint_id} result={r} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function ResultRow({ result: r }: { result: ProxyTestEndpointResult }) {
  const { t } = useTranslation()
  const cls = r.class ? CLASS_TEXT[r.class] : undefined
  return (
    <tr className="border-b align-top last:border-0" data-testid="test-result-row">
      <td className="py-2 pr-3">
        <span className="break-all font-mono text-xs">{r.address}</span>
      </td>
      <td className="py-2 pr-3">
        {r.ok ? (
          <TonePill tone="success" state="ok" label={t('proxyPools.test.ok', 'Works')} />
        ) : (
          <TonePill
            tone="destructive"
            state={r.class ?? 'failed'}
            label={cls ? t(cls.key, cls.en) : t('proxyPools.test.failed', 'Test failed')}
            detail={r.error || undefined}
          />
        )}
      </td>
      <td className="py-2 pr-3 text-xs text-muted-foreground">
        {r.ok ? t('proxyPools.test.ms', '{ms} ms', { ms: r.handshake_ms }) : '—'}
      </td>
      <td className="py-2 pr-3">
        <span className="font-mono text-xs">{r.ok ? r.exit_ip || '—' : '—'}</span>
      </td>
      <td className="py-2 text-xs text-muted-foreground">
        {r.ok ? (
          <span className="flex flex-wrap gap-x-2">
            <span>
              {(r.families ?? []).length > 0
                ? (r.families ?? [])
                    .map((f) =>
                      f === 'v4' ? t('proxyPools.test.v4', 'IPv4') : t('proxyPools.test.v6', 'IPv6')
                    )
                    .join(', ')
                : '—'}
            </span>
            {r.port_restricted === true && (
              <span data-testid="test-port-restricted">
                {t('proxyPools.test.portRestricted', 'Only port 443')}
              </span>
            )}
          </span>
        ) : (
          '—'
        )}
      </td>
    </tr>
  )
}
