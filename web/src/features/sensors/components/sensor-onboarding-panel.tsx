'use client'

/**
 * "Add sensor": the one place a sensor is added (api
 * docs/architecture/sensor-pairing.md, "Onboarding"; research/280, 356).
 * Shown in the Add sensor dialog and inline on the empty Sensors page.
 *
 * One path:
 * 1. Where it runs: Docker, Docker Compose, Kubernetes or Linux. The API
 *    renders the commands from the hardened templates of every install
 *    (read-only root, no capabilities, the checked seccomp profile, this
 *    instance's URL, the current release). No local policy is needed: the
 *    sensor follows the organization's scope; the host owner may narrow it.
 * 2. Run one command. It carries a single-use code, so this panel finds the
 *    sensor by itself; the sensor prints the same code, the link to approve
 *    it on and its fingerprint, and the command ends once it is paired.
 * 3. Approve: pick the fingerprint the host shows, re-authenticate.
 * A sensor started any other way prints its own link (/activate).
 */

import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { Check, ChevronDown, ExternalLink, KeyRound, Loader2, RefreshCw } from 'lucide-react'
import Link from '@/components/link'

import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useNow } from '@/hooks/use-now'
import { useSensor } from '@/lib/api/sensor-hooks'
import {
  createPairingExpectation,
  usePairingExpectation,
  useSensorInstallTemplates,
  type SensorPairingView,
} from '@/lib/api/sensor-pairing-hooks'
import type { Sensor } from '@/lib/api/sensor-types'
import { cn } from '@/lib/utils'

import {
  ONBOARDING_PLATFORMS,
  ONBOARDING_STAGES,
  TROUBLESHOOTING,
  healthCheckCommand,
  onboardingStage,
  stageIndex,
  type OnboardingPlatform,
  type OnboardingStage,
} from '../lib/onboarding'
import {
  formatCountdown,
  formatPairingCode,
  pairingErrorMessage,
  secondsUntil,
} from '../lib/pairing'
import { FIRST_HEARTBEAT_POLL_MS } from './sensor-install-flow'
import { Snippet, type SensorTemplates } from './sensor-install-snippets'
import { PairingReview } from './sensor-pairing-steps'

/** The console page a sensor's printed link opens. */
export const ACTIVATE_PATH = '/activate'

export interface SensorOnboardingPanelProps {
  /** The organization still allows API-key sensors and the viewer may create one. */
  canInstallWithKey?: boolean
  onInstallWithKey?: () => void
  /** Open the new sensor once it is online. */
  onOpenSensor?: (sensor: Sensor) => void
  /** Close the surrounding dialog (nothing in the inline variant). */
  onDone?: () => void
  /**
   * Make the command's code at once (the dialog: the person asked to add a
   * sensor). The inline empty state waits for a click instead, so a page
   * view never creates a code.
   */
  autoStart?: boolean
  className?: string
}

export function SensorOnboardingPanel({
  canInstallWithKey,
  onInstallWithKey,
  onOpenSensor,
  onDone,
  autoStart = true,
  className,
}: SensorOnboardingPanelProps) {
  const { t } = useTranslation()
  const ids = { where: useId(), run: useId() }
  const [platform, setPlatform] = useState<OnboardingPlatform>('docker')
  const [stage, setStage] = useState<OnboardingStage>('start')
  const runTitle =
    stage === 'compare'
      ? t('sensors.onboard.approve.title')
      : stage === 'approved' || stage === 'online'
        ? t('sensors.onboard.paired.title')
        : t('sensors.onboard.run.title')

  return (
    <div className={cn('space-y-6', className)} data-testid="sensor-onboarding">
      <PanelStep n={1} id={ids.where} title={t('sensors.onboard.where.title')}>
        <RadioGroup
          value={platform}
          onValueChange={(v) => setPlatform(v as OnboardingPlatform)}
          aria-labelledby={ids.where}
          className="grid grid-cols-2 gap-2 sm:grid-cols-4"
        >
          {ONBOARDING_PLATFORMS.map((p) => (
            <label
              key={p.key}
              htmlFor={`${ids.where}-${p.key}`}
              className={cn(
                'flex min-h-11 cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium transition-colors',
                platform === p.key ? 'border-primary bg-primary/5' : 'hover:bg-muted/40'
              )}
            >
              <RadioGroupItem id={`${ids.where}-${p.key}`} value={p.key} />
              {t(p.labelKey)}
            </label>
          ))}
        </RadioGroup>
      </PanelStep>

      <PanelStep n={2} id={ids.run} title={runTitle}>
        <InstallSession
          platform={platform}
          autoStart={autoStart}
          onStage={setStage}
          onOpenSensor={onOpenSensor}
          onDone={onDone}
        />
      </PanelStep>

      <div className="flex flex-col gap-3 border-t pt-4 text-sm sm:flex-row sm:items-center sm:justify-between">
        <span className="text-muted-foreground">
          {t('sensors.onboard.otherWay')}{' '}
          <Link
            href={ACTIVATE_PATH}
            className="inline-flex items-center gap-1 font-medium text-foreground underline-offset-4 hover:underline"
          >
            {t('sensors.onboard.enterCode')}
            <ExternalLink className="h-3.5 w-3.5" aria-hidden />
          </Link>
        </span>
        {canInstallWithKey && onInstallWithKey && (
          <Button variant="link" className="h-auto justify-start p-0" onClick={onInstallWithKey}>
            <KeyRound className="h-4 w-4" />
            {t('sensors.onboard.withKey')}
          </Button>
        )}
      </div>

      <Troubleshooting />
    </div>
  )
}

function PanelStep({
  n,
  id,
  title,
  children,
}: {
  n: number
  id: string
  title: string
  children: React.ReactNode
}) {
  return (
    <section aria-labelledby={id} className="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-3">
      <span
        aria-hidden
        className="grid size-7 place-items-center rounded-full border text-xs font-semibold text-muted-foreground"
      >
        {n}
      </span>
      <div className="min-w-0 space-y-3">
        <h3 id={id} className="pt-1 text-sm font-semibold">
          {title}
        </h3>
        {children}
      </div>
    </section>
  )
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

export function InstallCommands({
  platform,
  code,
}: {
  platform: OnboardingPlatform
  code: string | null
}) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useSensorInstallTemplates<SensorTemplates>(code)
  const option = ONBOARDING_PLATFORMS.find((p) => p.key === platform) ?? ONBOARDING_PLATFORMS[0]

  if (isLoading) return <Skeleton className="h-40 w-full" />
  if (error || !data) {
    return (
      <div
        role="alert"
        className="flex items-center justify-between gap-3 rounded-lg border p-3 text-sm"
      >
        <span className="text-destructive">{t('sensors.onboard.commandsFailed')}</span>
        <Button variant="outline" size="sm" onClick={() => void mutate()}>
          <RefreshCw className="h-4 w-4" />
          {t('sensors.onboard.retry')}
        </Button>
      </div>
    )
  }
  const text = data[option.field] ?? ''
  return (
    <div className="space-y-3">
      <Snippet text={text} label={t(option.labelKey)} file={option.file} />
      {platform === 'kubernetes' && (
        <p className="text-xs text-muted-foreground">{t('sensors.onboard.k8sOneSensor')}</p>
      )}
      {data.ca_fingerprint_sha256 && (
        <p className="text-xs text-muted-foreground" data-testid="onboarding-ca-fingerprint">
          {t('sensors.onboard.caFingerprint')}{' '}
          <code className="font-mono break-all">{data.ca_fingerprint_sha256}</code>
        </p>
      )}
      {data.policy && (
        <Collapsible className="rounded-lg border">
          <CollapsibleTrigger className="flex w-full items-center justify-between gap-2 px-3 py-2 text-start text-sm font-medium">
            <span className="min-w-0">
              <span className="block">{t('sensors.onboard.narrow.title')}</span>
              <span className="block text-xs font-normal text-muted-foreground">
                {t('sensors.onboard.narrow.text')}
              </span>
            </span>
            <ChevronDown className="h-4 w-4 shrink-0" aria-hidden />
          </CollapsibleTrigger>
          <CollapsibleContent className="space-y-2 border-t p-3">
            <p className="text-xs text-muted-foreground">{t('sensors.onboard.narrow.how')}</p>
            <Snippet
              text={data.policy}
              label={t('sensors.onboard.narrow.title')}
              file="sensor-policy.yaml"
            />
          </CollapsibleContent>
        </Collapsible>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// One install session: the command's code, the wait, the approval
// ---------------------------------------------------------------------------

/**
 * Poll the approved sensor until its first heartbeat. Module scope: SWR
 * restarts its timer whenever `refreshInterval` changes identity, and this
 * panel re-renders every second (the code's countdown).
 */
function sensorSeenInterval(s?: Sensor): number {
  return s?.last_seen_at ? 0 : FIRST_HEARTBEAT_POLL_MS
}

function InstallSession({
  platform,
  autoStart,
  onStage,
  onOpenSensor,
  onDone,
}: {
  platform: OnboardingPlatform
  autoStart: boolean
  /** Where the pairing stands, for the step's heading. */
  onStage?: (s: OnboardingStage) => void
  onOpenSensor?: (s: Sensor) => void
  onDone?: () => void
}) {
  const { t } = useTranslation()
  const [created, setCreated] = useState<SensorPairingView | null>(null)
  const [approved, setApproved] = useState<SensorPairingView | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const {
    data: polled,
    error: pollError,
    isValidating: checking,
    mutate: checkNow,
  } = usePairingExpectation(approved ? null : (created?.id ?? null))
  const view = polled ?? created
  const now = useNow(1000)
  const sensorId = approved?.sensor_id ?? null
  const { data: sensor } = useSensor(sensorId, { refreshInterval: sensorSeenInterval })
  const stage = onboardingStage(view, {
    approvedSensorId: sensorId,
    sensorSeen: !!sensor?.last_seen_at,
    now,
  })

  useEffect(() => {
    onStage?.(stage)
  }, [stage, onStage])

  const create = async () => {
    setError(null)
    setBusy(true)
    setApproved(null)
    try {
      setCreated(await createPairingExpectation({}))
    } catch (err) {
      setError(pairingErrorMessage(err, t('sensors.pair.err.create'), t))
    } finally {
      setBusy(false)
    }
  }

  // One code per opened dialog (a ref, so a re-render or a strict-mode
  // double effect never makes a second one).
  const started = useRef(false)
  useEffect(() => {
    if (!autoStart || started.current) return
    started.current = true
    void create()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once per mounted session
  }, [autoStart])

  if (!created) {
    return (
      <div className="space-y-3">
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : (
          <p className="text-sm text-muted-foreground">{t('sensors.onboard.run.intro')}</p>
        )}
        {busy ? (
          <Skeleton className="h-40 w-full" />
        ) : (
          <Button onClick={() => void create()}>
            {error ? t('sensors.onboard.retry') : t('sensors.onboard.run.show')}
          </Button>
        )}
      </div>
    )
  }

  const code = formatPairingCode(created.code ?? '')
  const left = secondsUntil(view?.expires_at, now)

  return (
    <div className="space-y-4">
      {(stage === 'waiting' || stage === 'ended') && (
        <>
          <p className="text-sm text-muted-foreground">{t('sensors.onboard.run.what')}</p>
          <InstallCommands platform={platform} code={code} />
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
            <span>
              {t('sensors.onboard.code.label')}{' '}
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono font-semibold">{code}</code>
            </span>
            {stage === 'waiting' && (
              <span className="text-muted-foreground tabular-nums">
                {t('sensors.onboard.code.expiresIn', undefined, { time: formatCountdown(left) })}
              </span>
            )}
          </div>
        </>
      )}

      <OnboardingStatus stage={stage} />

      {stage === 'waiting' && (
        <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
          <span
            role={pollError ? 'alert' : undefined}
            aria-live="polite"
            className={cn(pollError ? 'text-destructive' : 'text-muted-foreground')}
          >
            {pollError
              ? pairingErrorMessage(pollError, t('sensors.onboard.code.pollFailed'), t)
              : t('sensors.onboard.code.waiting')}
          </span>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void checkNow()}
            disabled={checking}
            aria-busy={checking}
          >
            <RefreshCw className={cn('h-4 w-4', checking && 'animate-spin')} />
            {t('sensors.onboard.code.checkNow')}
          </Button>
        </div>
      )}

      {stage === 'compare' && view && (
        <PairingReview view={view} onApproved={setApproved} onDone={() => onDone?.()} />
      )}

      {stage === 'ended' && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3 text-sm">
          <span role="alert">
            {view?.status === 'denied'
              ? t('sensors.onboard.code.closed')
              : t('sensors.onboard.code.ended')}
          </span>
          <Button variant="outline" size="sm" onClick={() => void create()} disabled={busy}>
            {t('sensors.onboard.code.newCommand')}
          </Button>
        </div>
      )}

      {(stage === 'approved' || stage === 'online') && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3 text-sm">
          <span aria-live="polite">
            {stage === 'online'
              ? t('sensors.onboard.online', undefined, { name: sensor?.name ?? '' })
              : t('sensors.onboard.approvedWaiting')}
          </span>
          <div className="flex gap-2">
            {stage === 'online' && sensor && onOpenSensor && (
              <Button variant="outline" size="sm" onClick={() => onOpenSensor(sensor)}>
                {t('sensors.onboard.openSensor')}
              </Button>
            )}
            {onDone && (
              <Button size="sm" onClick={onDone}>
                {t('sensors.pair.done')}
              </Button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

/** Waiting, compare, approved, online: where the pairing stands, live. */
export function OnboardingStatus({ stage }: { stage: OnboardingStage }) {
  const { t } = useTranslation()
  const current = stageIndex(stage)
  return (
    <ol
      className="grid gap-2 sm:grid-cols-4"
      aria-label={t('sensors.onboard.status.label')}
      data-testid="onboarding-status"
    >
      {ONBOARDING_STAGES.map((s, i) => {
        const done = i < current || (s === 'online' && stage === 'online')
        const active = i === current && stage !== 'online'
        return (
          <li
            key={s}
            aria-current={active ? 'step' : undefined}
            className="flex items-center gap-2 text-sm"
          >
            <span
              aria-hidden
              className={cn(
                'grid size-5 shrink-0 place-items-center rounded-full border',
                done && 'border-success bg-success text-background',
                active && 'border-primary'
              )}
            >
              {done ? (
                <Check className="h-3 w-3" />
              ) : active ? (
                <Loader2 className="h-3 w-3 animate-spin text-primary motion-reduce:animate-none" />
              ) : null}
            </span>
            <span className={cn(!done && !active && 'text-muted-foreground')}>
              {t(`sensors.onboard.status.${s}`)}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

// ---------------------------------------------------------------------------
// Troubleshooting
// ---------------------------------------------------------------------------

function Troubleshooting() {
  const { t } = useTranslation()
  const { data } = useSensorInstallTemplates<SensorTemplates>(null)
  const health = useMemo(() => healthCheckCommand(data?.api_url), [data?.api_url])
  return (
    <Collapsible className="rounded-lg border">
      <CollapsibleTrigger className="flex w-full items-center justify-between gap-2 px-3 py-2 text-sm font-medium">
        {t('sensors.onboard.trouble.title')}
        <ChevronDown className="h-4 w-4 shrink-0" aria-hidden />
      </CollapsibleTrigger>
      <CollapsibleContent className="border-t">
        <ul className="divide-y">
          {TROUBLESHOOTING.map((item) => (
            <li key={item.key} className="space-y-1.5 px-3 py-3 text-sm">
              <h4 className="font-medium">{t(`sensors.onboard.trouble.${item.key}.title`)}</h4>
              <div className="space-y-1.5">
                <span className="block text-xs text-muted-foreground">
                  {t('sensors.onboard.trouble.logSays')}
                </span>
                <span className="flex flex-wrap gap-1.5">
                  {item.lines.map((l) => (
                    <code
                      key={l}
                      className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs break-all"
                    >
                      {l}
                    </code>
                  ))}
                </span>
                <span className="block text-muted-foreground">
                  {t(`sensors.onboard.trouble.${item.key}.fix`)}
                </span>
                {item.key === 'unreachable' && health && (
                  <code className="block rounded bg-muted px-1.5 py-1 font-mono text-xs break-all">
                    {health}
                  </code>
                )}
              </div>
            </li>
          ))}
        </ul>
      </CollapsibleContent>
    </Collapsible>
  )
}
