'use client'

/**
 * System > Threat intelligence: how the platform receives its signed feeds
 * (api docs/rfcs/RFC-142-feed-relay.md). Direct: the platform fetches them.
 * Relay: one to three designated platform sensors download the files and the
 * platform verifies them with each feed's pinned keys, so it needs no
 * outbound access. Relay mode never falls back to direct by itself: the card
 * shows why a feed is stale with the fix, and the escape hatches (switch to
 * direct, an offline bundle) are explicit administrator actions. A change
 * needs a super admin and a fresh authenticator code; it is audited.
 */

import { useEffect, useId, useMemo, useState, type ReactNode } from 'react'
import { ExternalLink, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { SafeExternalLink } from '@/components/safe-external-link'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, RelativeTime } from '@/features/shared'
import { TonePill, type PillTone } from '@/features/shared/components/tone-pill'
import {
  saveFeedRelay,
  useFeedRelay,
  type FeedRelayFeed,
  type FeedRelayMode,
  type FeedRelayStatus,
} from '../api/use-feed-relay'
import { formatBytes } from '../lib/system'
import { handleSaveConflict } from './console-setting-parts'
import { stepUpErrorMessage } from './admin-confirm-dialog'

/** At most this many relay sensors may be designated. */
export const MAX_RELAYS = 3

const AIRGAP_GUIDE = 'https://docs.openctem.io/airgap/feeds/'

type Translate = (key: string, fallback: string, vars?: Record<string, string | number>) => string

/** One plain sentence for a stale reason, and the fix to take. */
export function staleReasonText(code: string, t: Translate): { message: string; fix: string } {
  const k = (name: string, message: string, fix: string) => ({
    message: t(`admin.feedRelay.reason.${name}`, message),
    fix: t(`admin.feedRelay.fix.${name}`, fix),
  })
  switch (code) {
    case 'no_relay_designated':
      return k(
        'no_relay_designated',
        'No relay sensor is designated.',
        'Choose one to three relay sensors below.'
      )
    case 'relay_offline':
      return k(
        'relay_offline',
        'No designated relay sensor has been seen for 10 minutes.',
        'Start or reconnect a relay sensor, or designate another one.'
      )
    case 'signer_refused':
      return k(
        'signer_refused',
        'The job signer refused to sign the round.',
        'Add the feed origin to SIGNER_FEED_ORIGINS on the signer, or correct the feed address.'
      )
    case 'sensor_refused':
      return k(
        'sensor_refused',
        'The relay sensor refused the round.',
        "Check the sensor's SENSOR_FEED_RELAY_ORIGINS and the job-signing key it trusts."
      )
    case 'upstream_missing':
      return k(
        'upstream_missing',
        'The relay could not find a file at the feed origin.',
        'Check the feed address (VULNFEED_BASE_URL).'
      )
    case 'nothing_delivered':
      return k(
        'nothing_delivered',
        'The relay delivered no file.',
        "Check the relay sensor's internet access and its log."
      )
    case 'pin_mismatch':
      return k(
        'pin_mismatch',
        'A relayed file did not match its pinned digest. Nothing was applied.',
        "The files may have been altered on the way: check the relay sensor's network path."
      )
    case 'verify_failed':
      return k(
        'verify_failed',
        'The relayed files did not verify against the pinned feed keys. Nothing was applied.',
        'Possible tampering: check the relay sensor and the feed origin.'
      )
    case 'rollback_refused':
      return k(
        'rollback_refused',
        'The relay delivered an older release than the one applied. Nothing was applied.',
        'Possible replay: check the relay sensor and the feed origin.'
      )
    case 'plan_failed':
    case 'import_failed':
      return k(
        'import_failed',
        'The relayed release could not be applied.',
        'Check the API log for the feed import; the next cycle retries.'
      )
    case 'round_expired':
      return k(
        'round_expired',
        'The relay did not finish the round in time.',
        "Check the relay sensor's connection; another relay takes over an idle round."
      )
    case 'spool_full':
      return k(
        'spool_full',
        'The relay spool is full.',
        'The next import frees it; if it persists, check the API log.'
      )
    default:
      return k(
        'unknown',
        'The last relay cycle failed.',
        'Check the API log; the next cycle retries.'
      )
  }
}

function feedLabel(feed: string, t: Translate): string {
  switch (feed) {
    case 'vulnfeed':
      return t('admin.feedRelay.feed.vulnfeed', 'Vulnerability feed')
    case 'versioncheck':
      return t('admin.feedRelay.feed.versioncheck', 'Release feed')
    case 'program_feed':
      return t('admin.feedRelay.feed.program_feed', 'Program feed')
    default:
      return feed
  }
}

/** The plain words of an open alert key. */
export function alertLabel(key: string, t: Translate): string {
  const [kind, feed = '', code = ''] = key.split(':')
  switch (kind) {
    case 'relay_offline':
      return t('admin.feedRelay.alert.relay_offline', 'No relay sensor online for over an hour')
    case 'feed_stale':
      return t('admin.feedRelay.alert.feed_stale', '{feed} is out of date', {
        feed: feedLabel(feed, t),
      })
    case 'round_failed':
      return t('admin.feedRelay.alert.round_failed', '{feed}: {reason}', {
        feed: feedLabel(feed, t),
        reason: staleReasonText(code, t).message,
      })
    default:
      return key
  }
}

function hours(seconds: number): number {
  return Math.max(0, Math.floor(seconds / 3600))
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 tabular-nums">{children}</dd>
    </>
  )
}

function modeTone(st: FeedRelayStatus): { tone: PillTone; state: string } {
  if (st.mode === 'direct') return { tone: 'muted', state: 'direct' }
  if (st.feeds.some((f) => f.stale_reason)) return { tone: 'warning', state: 'relay_degraded' }
  return { tone: 'success', state: 'relay' }
}

function FeedStatusRows({
  f,
  sensorName,
}: {
  f: FeedRelayFeed
  sensorName: (id?: string) => string
}) {
  const { t } = useTranslation()
  const never = t('admin.ti.neverRun', 'Never')
  const reason = f.stale_reason ? staleReasonText(f.stale_reason, t) : null
  return (
    <div className="space-y-2" data-feed={f.feed}>
      <p className="font-medium">{feedLabel(f.feed, t)}</p>
      {reason && (
        <div className="space-y-0.5" role="status" data-reason={f.stale_reason}>
          <p className="font-medium">{reason.message}</p>
          <p className="text-muted-foreground">{reason.fix}</p>
          {f.stale_detail && <p className="text-muted-foreground break-words">{f.stale_detail}</p>}
        </div>
      )}
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
        <Row label={t('admin.feedRelay.lastImport', 'Last good import')}>
          {f.last_import ? <RelativeTime date={f.last_import.created_at} /> : never}
        </Row>
        <Row label={t('admin.feedRelay.age', 'Feed age')}>
          {f.age_seconds != null
            ? t('admin.feedRelay.ageHours', '{n} hours', { n: hours(f.age_seconds) })
            : t('admin.feedRelay.ageUnknown', 'No release applied yet')}
        </Row>
        <Row label={t('admin.feedRelay.current', 'Current round')}>
          {f.current
            ? t(
                'admin.feedRelay.progress',
                '{phase}: {delivered} of {files} files, {bytes} received',
                {
                  phase: t(`admin.feedRelay.phase.${f.current.phase}`, f.current.phase),
                  delivered: f.current.delivered,
                  files: f.current.files,
                  bytes: formatBytes(f.current.bytes_delivered),
                }
              )
            : t('admin.feedRelay.idle', 'None (between cycles)')}
        </Row>
        {f.current && (
          <Row label={t('admin.feedRelay.claimedBy', 'Claimed by')}>
            {f.current.claimed_by
              ? sensorName(f.current.claimed_by)
              : t('admin.feedRelay.unclaimed', 'Waiting for a relay sensor')}
          </Row>
        )}
      </dl>
    </div>
  )
}

export function FeedRelayCard({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation()
  const groupId = useId()
  const { data, error, isLoading, mutate } = useFeedRelay()
  const [mode, setMode] = useState<FeedRelayMode>('direct')
  const [picked, setPicked] = useState<string[]>([])
  const [confirm, setConfirm] = useState<'save' | 'direct' | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (data) {
      setMode(data.mode)
      setPicked(data.sensor_ids)
    }
  }, [data])

  const names = useMemo(() => {
    const m = new Map<string, string>()
    for (const c of data?.candidates ?? []) m.set(c.id, c.name)
    for (const s of data?.sensors ?? []) if (s.name) m.set(s.id, s.name)
    return m
  }, [data])

  if (error) {
    return (
      <ErrorState
        title={t('admin.feedRelay.errorTitle', 'the feed delivery setting')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <Skeleton className="h-48 w-full" />

  const sensorName = (id?: string) =>
    (id && names.get(id)) || t('admin.feedRelay.unknownSensor', 'A sensor that is no longer listed')
  const eligible = data.candidates.filter((c) => c.eligible)
  const ineligible = data.candidates.filter((c) => !c.eligible)
  const samePick =
    picked.length === data.sensor_ids.length && picked.every((id) => data.sensor_ids.includes(id))
  const dirty = mode !== data.mode || (mode === 'relay' && !samePick)
  const valid = mode === 'direct' || (picked.length >= 1 && picked.length <= MAX_RELAYS)
  const pill = modeTone(data)

  const toggle = (id: string, on: boolean) =>
    setPicked((p) => (on ? [...p, id].slice(0, MAX_RELAYS) : p.filter((x) => x !== id)))

  const submit = async (next: FeedRelayMode, ids: string[]) => {
    setBusy(true)
    try {
      await saveFeedRelay({ mode: next, sensor_ids: ids, expected_version: data.version })
      toast.success(
        next === 'relay'
          ? t('admin.feedRelay.savedRelay', 'Feeds now come through the relay sensors.')
          : t('admin.feedRelay.savedDirect', 'The platform now fetches its feeds directly.')
      )
      setConfirm(null)
      void mutate()
    } catch (e) {
      if (
        !handleSaveConflict(
          e,
          () => void mutate(),
          t(
            'admin.settings.conflict',
            'Another administrator changed this setting. The latest values are shown.'
          )
        )
      )
        toast.error(stepUpErrorMessage(e, t))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card data-testid="feed-relay-card">
      <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0">
        <div className="min-w-0 space-y-1.5">
          <CardTitle>{t('admin.feedRelay.title', 'Feed delivery')}</CardTitle>
          <CardDescription>
            {t(
              'admin.feedRelay.description',
              "Direct: the platform fetches its feeds from the internet. Relay: designated platform sensors download the files and the platform verifies them with each feed's pinned keys, so it needs no outbound access."
            )}
          </CardDescription>
        </div>
        <TonePill
          tone={pill.tone}
          state={pill.state}
          label={
            data.mode === 'relay'
              ? t('admin.feedRelay.modeRelay', 'Relay')
              : t('admin.feedRelay.modeDirect', 'Direct')
          }
        />
      </CardHeader>
      <CardContent className="space-y-5 text-sm">
        {data.alerts.length > 0 && (
          <Alert role="alert">
            <AlertDescription>
              <p className="font-medium">
                {t('admin.feedRelay.alertsTitle', 'Administrators were alerted')}
              </p>
              <ul className="mt-1 space-y-0.5">
                {data.alerts.map((a) => (
                  <li key={a.key} data-alert={a.key}>
                    {alertLabel(a.key, t)}{' '}
                    <span className="text-muted-foreground">
                      (<RelativeTime date={a.since} />)
                    </span>
                  </li>
                ))}
              </ul>
            </AlertDescription>
          </Alert>
        )}

        {data.mode === 'relay' && (
          <>
            {data.bootstrap && data.sensors.length === 0 && (
              <p className="text-muted-foreground">
                {t(
                  'admin.feedRelay.bootstrap',
                  'Relay mode was chosen at install. The bundled sensor is designated as soon as it enrolls and reports that it can relay.'
                )}
              </p>
            )}
            {data.feeds.map((f) => (
              <FeedStatusRows key={f.feed} f={f} sensorName={sensorName} />
            ))}
            {data.not_relayed.length > 0 && (
              <p className="text-muted-foreground">
                {t(
                  'admin.feedRelay.notRelayed',
                  'Not relayed yet, so idle in relay mode: {feeds}.',
                  { feeds: data.not_relayed.map((f) => feedLabel(f, t)).join(', ') }
                )}
              </p>
            )}
            {data.sensors.length > 0 && (
              <div className="space-y-1.5">
                <p className="font-medium">{t('admin.feedRelay.relays', 'Relay sensors')}</p>
                <ul className="space-y-1">
                  {data.sensors.map((s) => (
                    <li
                      key={s.id}
                      className="flex flex-wrap items-center gap-x-3"
                      data-sensor={s.id}
                    >
                      <span className="font-medium">{sensorName(s.id)}</span>
                      <TonePill
                        tone={s.online ? 'success' : s.can_relay ? 'warning' : 'destructive'}
                        state={s.online ? 'online' : s.can_relay ? 'offline' : 'cannot_relay'}
                        label={
                          s.online
                            ? t('admin.feedRelay.online', 'Online')
                            : s.can_relay
                              ? t('admin.feedRelay.offline', 'Offline')
                              : t('admin.feedRelay.cannotRelay', 'Cannot relay')
                        }
                      />
                      <span className="text-muted-foreground">
                        {s.last_served_at ? (
                          <>
                            {t('admin.feedRelay.lastServed', 'Last round')}{' '}
                            <RelativeTime date={s.last_served_at} />
                          </>
                        ) : (
                          t('admin.feedRelay.neverServed', 'No round served yet')
                        )}
                      </span>
                      <span className="text-muted-foreground tabular-nums">
                        {t('admin.feedRelay.bytesToday', '{bytes} in the last 24 hours', {
                          bytes: formatBytes(s.bytes_today),
                        })}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <Separator />
          </>
        )}

        {data.locked ? (
          <p className="text-muted-foreground" data-locked={data.locked}>
            {data.locked === 'bundle_dir'
              ? t(
                  'admin.feedRelay.lockedBundle',
                  'Relay mode is not available: the server reads feeds from a bundle directory (VULNFEED_BUNDLE_DIR).'
                )
              : t(
                  'admin.feedRelay.lockedSigner',
                  'Relay mode is not available: no job signer is configured to sign relay rounds.'
                )}
          </p>
        ) : (
          <div className="space-y-4">
            <RadioGroup
              value={mode}
              onValueChange={(v) => setMode(v as FeedRelayMode)}
              disabled={!canEdit || busy}
              aria-label={t('admin.feedRelay.modeLabel', 'Feed delivery mode')}
              className="gap-2"
            >
              <div className="flex items-center gap-2">
                <RadioGroupItem value="direct" id={`${groupId}-direct`} />
                <Label htmlFor={`${groupId}-direct`}>
                  {t('admin.feedRelay.optionDirect', 'Direct: the platform fetches its feeds')}
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <RadioGroupItem value="relay" id={`${groupId}-relay`} />
                <Label htmlFor={`${groupId}-relay`}>
                  {t('admin.feedRelay.optionRelay', 'Relay: platform sensors bring the feeds')}
                </Label>
              </div>
            </RadioGroup>

            {mode === 'relay' && (
              <fieldset className="space-y-2" disabled={!canEdit || busy}>
                <legend className="font-medium">
                  {t('admin.feedRelay.pickTitle', 'Relay sensors (one to three)')}
                </legend>
                {eligible.length === 0 ? (
                  <p className="text-muted-foreground">
                    {t(
                      'admin.feedRelay.noEligible',
                      'No platform sensor can relay yet. A shared sensor with a pinned job-signing key relays unless its host sets SENSOR_FEED_RELAY=0.'
                    )}
                  </p>
                ) : (
                  <ul className="space-y-1.5">
                    {eligible.map((c) => {
                      const on = picked.includes(c.id)
                      return (
                        <li key={c.id} className="flex items-center gap-2">
                          <Checkbox
                            id={`${groupId}-${c.id}`}
                            checked={on}
                            disabled={!on && picked.length >= MAX_RELAYS}
                            onCheckedChange={(v) => toggle(c.id, v === true)}
                          />
                          <Label htmlFor={`${groupId}-${c.id}`}>{c.name}</Label>
                          {c.last_seen_at && (
                            <span className="text-muted-foreground">
                              {t('admin.feedRelay.seen', 'seen')}{' '}
                              <RelativeTime date={c.last_seen_at} />
                            </span>
                          )}
                        </li>
                      )
                    })}
                  </ul>
                )}
                {ineligible.length > 0 && (
                  <p className="text-muted-foreground" data-testid="feed-relay-ineligible">
                    {t(
                      'admin.feedRelay.ineligible',
                      'Not offered: {list}. Only active platform sensors that report they can relay are listed; a sensor cannot relay when its host sets SENSOR_FEED_RELAY=0, it has no pinned job-signing key, or its release is too old. Organizations’ sensors never relay.',
                      {
                        list: ineligible
                          .map((c) =>
                            c.reason === 'inactive'
                              ? t('admin.feedRelay.whyInactive', '{name} (not active)', {
                                  name: c.name,
                                })
                              : t('admin.feedRelay.whyNoCap', '{name} (cannot relay)', {
                                  name: c.name,
                                })
                          )
                          .join(', '),
                      }
                    )}
                  </p>
                )}
              </fieldset>
            )}

            {canEdit && (
              <div className="flex flex-wrap justify-end gap-2">
                {data.mode === 'relay' && (
                  <Button variant="outline" disabled={busy} onClick={() => setConfirm('direct')}>
                    {t('admin.feedRelay.switchDirect', 'Switch to direct now')}
                  </Button>
                )}
                <Button disabled={!dirty || !valid || busy} onClick={() => setConfirm('save')}>
                  {busy && <Loader2 className="me-1.5 size-4 animate-spin" />}
                  {t('admin.settings.save', 'Save')}
                </Button>
              </div>
            )}
          </div>
        )}

        {data.mode === 'relay' && (
          <p className="text-muted-foreground">
            {t(
              'admin.feedRelay.offlineHint',
              'No sensor can reach the feeds? A super admin can switch to direct above, or load a signed offline feed bundle on the server.'
            )}{' '}
            <SafeExternalLink
              href={AIRGAP_GUIDE}
              className="inline-flex items-center gap-1 underline underline-offset-2"
            >
              {t('admin.feedRelay.offlineGuide', 'Offline bundle guide')}
              <ExternalLink className="size-3.5" aria-hidden />
            </SafeExternalLink>
          </p>
        )}
      </CardContent>

      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={
          confirm === 'direct' || (confirm === 'save' && mode === 'direct')
            ? t('admin.feedRelay.confirmDirectTitle', 'Fetch feeds directly?')
            : t('admin.feedRelay.confirmRelayTitle', 'Receive feeds through the relay?')
        }
        desc={
          confirm === 'direct' || (confirm === 'save' && mode === 'direct')
            ? t(
                'admin.feedRelay.confirmDirect',
                'The platform will make outbound requests to the feed hosts itself. Use this only if the platform is allowed to reach the internet. You will be asked for a fresh authenticator code.'
              )
            : t(
                'admin.feedRelay.confirmRelay',
                'The platform stops fetching feeds itself and receives them only through the selected sensors. It never falls back to direct by itself; administrators are alerted if no relay is seen for an hour. You will be asked for a fresh authenticator code.'
              )
        }
        destructive={confirm === 'direct'}
        confirmText={
          confirm === 'direct'
            ? t('admin.feedRelay.switchDirect', 'Switch to direct now')
            : t('admin.settings.save', 'Save')
        }
        isLoading={busy}
        handleConfirm={() =>
          void (confirm === 'direct' || mode === 'direct'
            ? submit('direct', [])
            : submit('relay', picked))
        }
      />
    </Card>
  )
}
