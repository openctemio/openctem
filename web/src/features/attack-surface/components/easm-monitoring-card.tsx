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
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useSettleSignal } from '@/features/shared/components/settle-group'
import { useTranslation } from '@/context/i18n-provider'
import { RelativeTime } from '@/features/shared'
import type { EASMSettings } from '@/lib/api/generated'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission, useCanMutate } from '@/lib/permissions'
import {
  runEASMSweep,
  saveEASMSettings,
  useEASMSettings,
  type EASMSettingsInput,
} from '../hooks/use-easm-settings'

/** Interval choices in hours; 0 is the platform default. */
export const EASM_INTERVALS = [0, 6, 12, 24, 48, 168]

type TFn = ReturnType<typeof useTranslation>['t']

function intervalLabel(t: TFn, h: number, platformDefault?: number) {
  if (h === 0) {
    return platformDefault
      ? t('attackSurface.monitoring.intervalDefaultHours', 'Default ({hours} h)', {
          hours: platformDefault,
        })
      : t('attackSurface.monitoring.intervalDefault', 'Default')
  }
  if (h === 168) return t('attackSurface.monitoring.intervalWeekly', 'Weekly')
  return t('attackSurface.monitoring.intervalHours', 'Every {hours} h', { hours: h })
}

function inputOf(s: EASMSettings) {
  return {
    ct_enabled: !!s.ct_enabled,
    dns_checks_enabled: !!s.dns_checks_enabled,
    ct_interval_hours: s.ct_interval_hours ?? 0,
    dns_interval_hours: s.dns_interval_hours ?? 0,
  }
}

type PendingKey = 'run' | 'enrichment' | 'screenshots' | 'lookalike' | 'network'

const PENDING_CHANGE: Record<Exclude<PendingKey, 'run'>, Partial<EASMSettingsInput>> = {
  enrichment: { enrichment_enabled: true },
  screenshots: { web_screenshots_enabled: true },
  lookalike: { lookalike_ct_enabled: true },
  network: { network_lookups_enabled: true },
}

export function EASMMonitoringCard() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  // Owner or admin (the API gate): organization settings change by role.
  const canSettings = useCanMutate('PUT /api/v1/easm/settings')
  const canRun = can(Permission.ScopeWrite)
  const { settings, isLoading, mutate, enabled } = useEASMSettings()
  useSettleSignal(isLoading)
  const [busy, setBusy] = useState(false)
  // Starting a run or turning on a lookup asks first; turning one off does not.
  const [pending, setPending] = useState<PendingKey | null>(null)
  // Re-read the clock once a minute so "Run now" comes back on its own.
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 60_000)
    return () => clearInterval(id)
  }, [])

  if (!enabled || isLoading || !settings) return null

  const save = async (change: Partial<EASMSettingsInput>) => {
    setBusy(true)
    try {
      const next = await saveEASMSettings({ ...inputOf(settings), ...change })
      void mutate(next, { revalidate: false })
      toast.success(t('attackSurface.monitoring.saved', 'Monitoring settings saved.'))
    } catch (e) {
      toast.error(
        getErrorMessage(e, t('attackSurface.monitoring.saveFailed', 'Could not save the settings'))
      )
    } finally {
      setBusy(false)
    }
  }

  const runNow = async () => {
    setBusy(true)
    try {
      await runEASMSweep()
      toast.success(
        t(
          'attackSurface.monitoring.runStarted',
          'Discovery and DNS checks started. Results appear in a few minutes.'
        )
      )
      setNow(Date.now())
      void mutate()
    } catch (e) {
      toast.error(
        getErrorMessage(e, t('attackSurface.monitoring.runFailed', 'Could not start the run'))
      )
      void mutate()
    } finally {
      setBusy(false)
    }
  }

  const confirmCopy = {
    run: {
      title: t('confirm.easm.runTitle', 'Run discovery and DNS checks now?'),
      desc: t(
        'confirm.easm.runDesc',
        'Certificate Transparency discovery and DNS lookups start right away for your verified domains. Results appear in a few minutes and you can run again after 15 minutes.'
      ),
      button: t('confirm.easm.runButton', 'Run now'),
    },
    enrichment: {
      title: t('confirm.easm.enrichmentTitle', 'Turn on automatic enrichment?'),
      desc: t(
        'confirm.easm.enrichmentDesc',
        'Every new asset in scope is looked up at once through public DNS, registration and network-owner sources. Nothing is sent to your hosts. You can turn it off again at any time.'
      ),
      button: t('confirm.easm.enrichmentButton', 'Turn on enrichment'),
    },
    screenshots: {
      title: t('confirm.easm.screenshotsTitle', 'Keep screenshots of web assets?'),
      desc: t(
        'confirm.easm.screenshotsDesc',
        'Sensors with the screenshot tool will visit your web assets and the screenshots are kept for 30 days. A screenshot shows whatever the page shows. Turning it off stops new screenshots.'
      ),
      button: t('confirm.easm.screenshotsButton', 'Keep screenshots'),
    },
    lookalike: {
      title: t('confirm.easm.lookalikeTitle', 'Check lookalike domains in crt.sh?'),
      desc: t(
        'confirm.easm.lookalikeDesc',
        'The names of registered lookalikes of your domains are sent to crt.sh to see whether they hold certificates. You can turn it off again at any time.'
      ),
      button: t('confirm.easm.lookalikeButton', 'Turn on certificate checks'),
    },
    network: {
      title: t('confirm.easm.networkTitle', 'Look up network seeds in RIPEstat?'),
      desc: t(
        'confirm.easm.networkDesc',
        'Your AS numbers and organization names are sent to RIPEstat to find your address ranges. You can turn it off again at any time.'
      ),
      button: t('confirm.easm.networkButton', 'Turn on lookups'),
    },
  }
  const copy = pending ? confirmCopy[pending] : null

  const waitUntil = settings.run_now_available_at ? new Date(settings.run_now_available_at) : null
  const waiting = !!waitUntil && waitUntil.getTime() > now

  return (
    <Card className="lg:col-span-3">
      <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
        <div>
          <CardTitle className="text-base">
            {t('attackSurface.monitoring.title', 'Monitoring')}
          </CardTitle>
          <CardDescription>
            {t(
              'attackSurface.monitoring.description',
              'Certificate Transparency discovery and DNS checks run on their own; you can also run them now.'
            )}
          </CardDescription>
        </div>
        {canRun && (
          <Button
            size="sm"
            variant="outline"
            disabled={busy || waiting}
            onClick={() => setPending('run')}
            title={
              waiting
                ? t(
                    'attackSurface.monitoring.runWait',
                    'You can run again 15 minutes after the last run'
                  )
                : undefined
            }
          >
            <Play className="me-2 h-4 w-4" aria-hidden />
            {t('attackSurface.monitoring.runNow', 'Run now')}
          </Button>
        )}
      </CardHeader>
      <CardContent className="grid gap-6 md:grid-cols-2">
        <section
          className="space-y-3"
          aria-label={t('attackSurface.monitoring.ct', 'Certificate Transparency discovery')}
        >
          <div className="flex items-center justify-between gap-3">
            <Label htmlFor="easm-ct" className="font-medium">
              {t('attackSurface.monitoring.ct', 'Certificate Transparency discovery')}
            </Label>
            <Switch
              id="easm-ct"
              checked={!!settings.ct_enabled}
              disabled={!canSettings || busy || !settings.ct_available}
              onCheckedChange={(on) => void save({ ct_enabled: on })}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            {t(
              'attackSurface.monitoring.ctDescription',
              'Your domain names are sent to crt.sh and Cert Spotter to find certificates issued for them. Turn this off to keep them private; no new names are then discovered this way.'
            )}
          </p>
          <div className="flex items-center justify-between gap-3 text-sm">
            <span className="text-muted-foreground">
              {t('attackSurface.monitoring.lastRun', 'Last run')}
            </span>
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

        <section className="space-y-3" aria-label={t('attackSurface.monitoring.dns', 'DNS checks')}>
          <div className="flex items-center justify-between gap-3">
            <Label htmlFor="easm-dns" className="font-medium">
              {t('attackSurface.monitoring.dns', 'DNS checks')}
            </Label>
            <Switch
              id="easm-dns"
              checked={!!settings.dns_checks_enabled}
              disabled={!canSettings || busy || !settings.dns_available}
              onCheckedChange={(on) => void save({ dns_checks_enabled: on })}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            {t(
              'attackSurface.monitoring.dnsDescription',
              'Dangling CNAME and NS records, lame delegations and email security (SPF, DMARC), looked up through DNS only.'
            )}
          </p>
          <div className="flex items-center justify-between gap-3 text-sm">
            <span className="text-muted-foreground">
              {t('attackSurface.monitoring.lastRun', 'Last run')}
            </span>
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

        <section
          className="space-y-3 md:col-span-2"
          aria-label={t('assetFreshness.settings.title', 'Automatic enrichment')}
        >
          <div className="flex items-center justify-between gap-3">
            <Label htmlFor="easm-enrichment" className="font-medium">
              {t('assetFreshness.settings.title', 'Automatic enrichment')}
            </Label>
            <Switch
              id="easm-enrichment"
              checked={!!settings.enrichment_enabled}
              disabled={!canSettings || busy || !settings.enrichment_available}
              onCheckedChange={(on) =>
                on ? setPending('enrichment') : void save({ enrichment_enabled: false })
              }
            />
          </div>
          <p className="text-xs text-muted-foreground">
            {t(
              'assetFreshness.settings.description',
              'Every new asset in your scope is enriched at once: DNS records, domain registration and the network owner of its addresses. Only public lookups are used; nothing is sent to your hosts.'
            )}
          </p>
          {!settings.enrichment_available && (
            <p className="text-xs text-muted-foreground">
              {t(
                'assetFreshness.settings.unavailable',
                'Turned off for the whole platform by the operator.'
              )}
            </p>
          )}
        </section>
        <section
          className="space-y-3 md:col-span-2"
          aria-label={t('lookalikes.ct.title', 'Certificate checks of lookalike domains')}
        >
          <div className="flex items-center justify-between gap-3">
            <Label htmlFor="easm-lookalike-ct" className="font-medium">
              {t('lookalikes.ct.title', 'Certificate checks of lookalike domains')}
            </Label>
            <Switch
              id="easm-lookalike-ct"
              checked={!!settings.lookalike_ct_enabled}
              disabled={!canSettings || busy}
              onCheckedChange={(on) =>
                on ? setPending('lookalike') : void save({ lookalike_ct_enabled: false })
              }
            />
          </div>
          <p className="text-xs text-muted-foreground">
            {t(
              'lookalikes.ct.description',
              'Registered lookalikes of your domains are looked up in crt.sh to see whether they hold certificates. Turn this off to keep those names private; lookalikes are then checked through DNS only.'
            )}
          </p>
        </section>
        <section
          className="space-y-3 md:col-span-2"
          aria-label={t('networkSeeds.lookups.title', 'Network seed lookups')}
        >
          <div className="flex items-center justify-between gap-3">
            <Label htmlFor="easm-network-lookups" className="font-medium">
              {t('networkSeeds.lookups.title', 'Network seed lookups')}
            </Label>
            <Switch
              id="easm-network-lookups"
              checked={!!settings.network_lookups_enabled}
              disabled={!canSettings || busy}
              onCheckedChange={(on) =>
                on ? setPending('network') : void save({ network_lookups_enabled: false })
              }
            />
          </div>
          <p className="text-xs text-muted-foreground">
            {t(
              'networkSeeds.lookups.description',
              'Your AS numbers and organization names are sent to RIPEstat to find your address ranges. Turn this off to keep them private; network seeds are then not looked up.'
            )}
          </p>
        </section>
        <section
          className="space-y-3 md:col-span-2"
          aria-label={t('webEvidence.settings.title', 'Screenshots of web assets')}
        >
          <div className="flex items-center justify-between gap-3">
            <Label htmlFor="easm-screenshots" className="font-medium">
              {t('webEvidence.settings.title', 'Screenshots of web assets')}
            </Label>
            <Switch
              id="easm-screenshots"
              checked={!!settings.web_screenshots_enabled}
              disabled={!canSettings || busy}
              onCheckedChange={(on) =>
                on ? setPending('screenshots') : void save({ web_screenshots_enabled: false })
              }
            />
          </div>
          <p className="text-xs text-muted-foreground">
            {t(
              'webEvidence.settings.description',
              'Keep the screenshots that sensors with the screenshot tool take of your web assets, for 30 days. A screenshot shows whatever the page shows, so this is off by default. Status, title and a short masked response are kept either way.'
            )}
          </p>
        </section>
        <DigestSection settings={settings} disabled={!canSettings || busy} onSave={save} />
      </CardContent>
      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(o) => !o && setPending(null)}
        title={copy?.title ?? ''}
        desc={copy?.desc ?? ''}
        confirmText={copy?.button}
        isLoading={busy}
        handleConfirm={async () => {
          const key = pending
          setPending(null)
          if (key === 'run') await runNow()
          else if (key) await save(PENDING_CHANGE[key])
        }}
      />
    </Card>
  )
}

/** ISO weekdays, 1 = Monday .. 7 = Sunday (the API's digest_weekday). */
const WEEKDAYS = [1, 2, 3, 4, 5, 6, 7] as const

function DigestSection({
  settings,
  disabled,
  onSave,
}: {
  settings: EASMSettings
  disabled: boolean
  onSave: (change: Partial<EASMSettingsInput>) => Promise<void>
}) {
  const { t, locale } = useTranslation()
  const dayName = (d: number) =>
    // 2024-01-01 was a Monday: day d of that week, named in the user's language.
    new Date(Date.UTC(2024, 0, d)).toLocaleDateString(locale, { weekday: 'long', timeZone: 'UTC' })
  const enabled = !!settings.weekly_digest_enabled
  return (
    <section
      className="space-y-3 md:col-span-2"
      aria-label={t('attackSurface.digest.title', 'Weekly digest')}
    >
      <div className="flex items-center justify-between gap-3">
        <Label htmlFor="easm-digest" className="font-medium">
          {t('attackSurface.digest.title', 'Weekly digest')}
        </Label>
        <Switch
          id="easm-digest"
          checked={enabled}
          disabled={disabled}
          onCheckedChange={(on) => void onSave({ weekly_digest_enabled: on })}
        />
      </div>
      <p className="text-xs text-muted-foreground">
        {t(
          'attackSurface.digest.description',
          'Once a week, administrators and the notification channels that receive attack surface events get a summary of what changed: new and removed hosts, ports, certificates, DNS records, technologies and exposures. A week without changes sends nothing.'
        )}
      </p>
      <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
        <Label htmlFor="easm-digest-day" className="font-normal text-muted-foreground">
          {t('attackSurface.digest.day', 'Sent on (at {hour}:00 UTC)', {
            hour: String(settings.digest_hour_utc ?? 8).padStart(2, '0'),
          })}
        </Label>
        <Select
          value={String(settings.digest_weekday ?? 1)}
          disabled={disabled || !enabled}
          onValueChange={(v) => void onSave({ digest_weekday: Number(v) })}
        >
          <SelectTrigger id="easm-digest-day" className="h-8 w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {WEEKDAYS.map((d) => (
              <SelectItem key={d} value={String(d)}>
                {dayName(d)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="flex items-center justify-between gap-3 text-sm">
        <span className="text-muted-foreground">{t('attackSurface.digest.last', 'Last sent')}</span>
        <span>
          {settings.last_digest_at ? <RelativeTime date={settings.last_digest_at} /> : '—'}
        </span>
      </div>
    </section>
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
  const { t } = useTranslation()
  return (
    <div className="flex items-center justify-between gap-3 text-sm">
      <Label htmlFor={id} className="font-normal text-muted-foreground">
        {t('attackSurface.monitoring.howOften', 'How often')}
      </Label>
      <Select value={String(value)} disabled={disabled} onValueChange={(v) => onChange(Number(v))}>
        <SelectTrigger id={id} className="h-8 w-40">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {EASM_INTERVALS.map((h) => (
            <SelectItem key={h} value={String(h)}>
              {intervalLabel(t, h, h === 0 && value !== 0 ? undefined : platformDefault)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}
