'use client'

/**
 * Attack-surface monitoring (research/22 P0-11): when Certificate
 * Transparency and the DNS checks last ran, the organization's switches and
 * cadence, and "Run now". The server is the boundary: it takes the tenant
 * from the session, enforces the 6-hour floor and the 15-minute run-now
 * limit, and audits every change.
 */

import { useEffect, useState } from 'react'
import { Play } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { RelativeTime } from '@/features/shared'
import type { EASMSettings } from '@/lib/api/generated'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import { runEASMSweep, saveEASMSettings, useEASMSettings } from '../hooks/use-easm-settings'

/** Interval choices in hours; 0 is the platform default. */
export const EASM_INTERVALS = [0, 6, 12, 24, 48, 168]

function intervalLabel(h: number, platformDefault?: number) {
  if (h === 0) return platformDefault ? `Default (${platformDefault} h)` : 'Default'
  if (h === 168) return 'Weekly'
  return `Every ${h} h`
}

function inputOf(s: EASMSettings) {
  return {
    ct_enabled: !!s.ct_enabled,
    dns_checks_enabled: !!s.dns_checks_enabled,
    ct_interval_hours: s.ct_interval_hours ?? 0,
    dns_interval_hours: s.dns_interval_hours ?? 0,
  }
}

export function EASMMonitoringCard() {
  const { can } = usePermissions()
  const canSettings = can(Permission.SettingsWrite)
  const canRun = can(Permission.ScopeWrite)
  const { settings, isLoading, mutate, enabled } = useEASMSettings()
  const [busy, setBusy] = useState(false)
  // Re-read the clock once a minute so "Run now" comes back on its own.
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 60_000)
    return () => clearInterval(id)
  }, [])

  if (!enabled || isLoading || !settings) return null

  const save = async (change: Partial<ReturnType<typeof inputOf>>) => {
    setBusy(true)
    try {
      const next = await saveEASMSettings({ ...inputOf(settings), ...change })
      void mutate(next, { revalidate: false })
      toast.success('Monitoring settings saved')
    } catch (e) {
      toast.error(getErrorMessage(e, 'Could not save the settings'))
    } finally {
      setBusy(false)
    }
  }

  const runNow = async () => {
    setBusy(true)
    try {
      await runEASMSweep()
      toast.success('Discovery and DNS checks started. Results appear in a few minutes.')
      setNow(Date.now())
      void mutate()
    } catch (e) {
      toast.error(getErrorMessage(e, 'Could not start the run'))
      void mutate()
    } finally {
      setBusy(false)
    }
  }

  const waitUntil = settings.run_now_available_at ? new Date(settings.run_now_available_at) : null
  const waiting = !!waitUntil && waitUntil.getTime() > now

  return (
    <Card className="lg:col-span-3">
      <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
        <div>
          <CardTitle className="text-base">Monitoring</CardTitle>
          <CardDescription>
            Certificate Transparency discovery and DNS checks run on their own; you can also run
            them now.
          </CardDescription>
        </div>
        {canRun && (
          <Button
            size="sm"
            variant="outline"
            disabled={busy || waiting}
            onClick={() => void runNow()}
            title={waiting ? 'You can run again 15 minutes after the last run' : undefined}
          >
            <Play className="me-2 h-4 w-4" aria-hidden />
            Run now
          </Button>
        )}
      </CardHeader>
      <CardContent className="grid gap-6 md:grid-cols-2">
        <section className="space-y-3" aria-label="Certificate Transparency">
          <div className="flex items-center justify-between gap-3">
            <Label htmlFor="easm-ct" className="font-medium">
              Certificate Transparency discovery
            </Label>
            <Switch
              id="easm-ct"
              checked={!!settings.ct_enabled}
              disabled={!canSettings || busy || !settings.ct_available}
              onCheckedChange={(on) => void save({ ct_enabled: on })}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            Your domain names are sent to crt.sh and Cert Spotter to find certificates issued for
            them. Turn this off to keep them private; no new names are then discovered this way.
          </p>
          <div className="flex items-center justify-between gap-3 text-sm">
            <span className="text-muted-foreground">Last run</span>
            <span>
              {settings.last_ct_sweep_at ? <RelativeTime date={settings.last_ct_sweep_at} /> : '—'}
            </span>
          </div>
          <IntervalSelect
            id="easm-ct-interval"
            value={settings.ct_interval_hours ?? 0}
            platformDefault={settings.ct_effective_interval_hours}
            disabled={!canSettings || busy || !settings.ct_enabled}
            onChange={(h) => void save({ ct_interval_hours: h })}
          />
        </section>

        <section className="space-y-3" aria-label="DNS checks">
          <div className="flex items-center justify-between gap-3">
            <Label htmlFor="easm-dns" className="font-medium">
              DNS checks
            </Label>
            <Switch
              id="easm-dns"
              checked={!!settings.dns_checks_enabled}
              disabled={!canSettings || busy || !settings.dns_available}
              onCheckedChange={(on) => void save({ dns_checks_enabled: on })}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            Dangling CNAME and NS records, lame delegations and email security (SPF, DMARC), looked
            up through DNS only.
          </p>
          <div className="flex items-center justify-between gap-3 text-sm">
            <span className="text-muted-foreground">Last run</span>
            <span>
              {settings.last_dns_check_at ? (
                <RelativeTime date={settings.last_dns_check_at} />
              ) : (
                '—'
              )}
            </span>
          </div>
          <IntervalSelect
            id="easm-dns-interval"
            value={settings.dns_interval_hours ?? 0}
            platformDefault={settings.dns_effective_interval_hours}
            disabled={!canSettings || busy || !settings.dns_checks_enabled}
            onChange={(h) => void save({ dns_interval_hours: h })}
          />
        </section>
      </CardContent>
    </Card>
  )
}

function IntervalSelect({
  id,
  value,
  platformDefault,
  disabled,
  onChange,
}: {
  id: string
  value: number
  platformDefault?: number
  disabled: boolean
  onChange: (hours: number) => void
}) {
  return (
    <div className="flex items-center justify-between gap-3 text-sm">
      <Label htmlFor={id} className="font-normal text-muted-foreground">
        How often
      </Label>
      <Select value={String(value)} disabled={disabled} onValueChange={(v) => onChange(Number(v))}>
        <SelectTrigger id={id} className="h-8 w-40">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {EASM_INTERVALS.map((h) => (
            <SelectItem key={h} value={String(h)}>
              {intervalLabel(h, h === 0 && value !== 0 ? undefined : platformDefault)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}
