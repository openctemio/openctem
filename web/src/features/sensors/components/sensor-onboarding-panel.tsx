'use client'

/**
 * "Add sensor": the one place a sensor is added (api
 * docs/architecture/sensor-pairing.md, "Onboarding"; research/280). Shown
 * inline on the empty Sensors page and in the Add sensor dialog.
 *
 * 1. Where it runs: Docker, Docker Compose, Kubernetes or Linux. The API
 *    renders the commands from the same hardened templates as every install
 *    (read-only root, no capabilities, the checked seccomp profile, the local
 *    policy, this instance's URL, the current release).
 * 2. How it joins: create a pairing code first (the command carries it, the
 *    panel waits for the sensor live), or start the sensor and enter the code
 *    it prints. Both end in the fingerprint compare and the step-up approval;
 *    no secret is ever copied.
 * 3. Troubleshooting keyed by what the sensor prints.
 */

import { useId, useMemo, useState } from 'react'
import { Check, ChevronDown, KeyRound, Loader2, RefreshCw } from 'lucide-react'

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
  type JoinMethod,
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
import { EnterCodePanel, PairingReview } from './sensor-pairing-steps'

export interface SensorOnboardingPanelProps {
  /** The organization still allows API-key sensors and the viewer may create one. */
  canInstallWithKey?: boolean
  onInstallWithKey?: () => void
  /** Open the new sensor once it is online. */
  onOpenSensor?: (sensor: Sensor) => void
  /** Close the surrounding dialog (nothing in the inline variant). */
  onDone?: () => void
  className?: string
}

export function SensorOnboardingPanel({
  canInstallWithKey,
  onInstallWithKey,
  onOpenSensor,
  onDone,
  className,
}: SensorOnboardingPanelProps) {
  const { t } = useTranslation()
  const ids = { where: useId(), how: useId(), run: useId() }
  const [platform, setPlatform] = useState<OnboardingPlatform>('docker')
  const [method, setMethod] = useState<JoinMethod>('code')

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
                'flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium transition-colors',
                platform === p.key ? 'border-primary bg-primary/5' : 'hover:bg-muted/40'
              )}
            >
              <RadioGroupItem id={`${ids.where}-${p.key}`} value={p.key} />
              {t(p.labelKey)}
            </label>
          ))}
        </RadioGroup>
      </PanelStep>

      <PanelStep n={2} id={ids.how} title={t('sensors.onboard.how.title')}>
        <RadioGroup
          value={method}
          onValueChange={(v) => setMethod(v as JoinMethod)}
          aria-labelledby={ids.how}
          className="grid gap-3 sm:grid-cols-2"
        >
          {(['code', 'interactive'] as const).map((m) => (
            <label
              key={m}
              htmlFor={`${ids.how}-${m}`}
              className={cn(
                'flex cursor-pointer gap-3 rounded-lg border p-3 text-sm transition-colors',
                method === m ? 'border-primary bg-primary/5' : 'hover:bg-muted/40'
              )}
            >
              <RadioGroupItem id={`${ids.how}-${m}`} value={m} className="mt-0.5" />
              <span className="min-w-0">
                <span className="block font-medium">{t(`sensors.onboard.how.${m}.title`)}</span>
                <span className="block text-muted-foreground">
                  {t(`sensors.onboard.how.${m}.text`)}
                </span>
              </span>
            </label>
          ))}
        </RadioGroup>
      </PanelStep>

      <PanelStep n={3} id={ids.run} title={t('sensors.onboard.run.title')}>
        {method === 'code' ? (
          <CodeFirst platform={platform} onOpenSensor={onOpenSensor} onDone={onDone} />
        ) : (
          <Interactive platform={platform} onDone={onDone} />
        )}
      </PanelStep>

      <div className="flex flex-col gap-3 border-t pt-4 text-sm sm:flex-row sm:items-center sm:justify-between">
        {canInstallWithKey && onInstallWithKey ? (
          <Button variant="link" className="h-auto p-0" onClick={onInstallWithKey}>
            <KeyRound className="h-4 w-4" />
            {t('sensors.onboard.withKey')}
          </Button>
        ) : (
          <span className="text-muted-foreground">{t('sensors.onboard.noSecret')}</span>
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
// The commands
// ---------------------------------------------------------------------------

function InstallCommands({
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
      {data.policy && (
        <Collapsible className="rounded-lg border">
          <CollapsibleTrigger className="flex w-full items-center justify-between gap-2 px-3 py-2 text-start text-sm font-medium">
            <span className="min-w-0">
              <span className="block">{t('sensors.onboard.policy.title')}</span>
              <span className="block text-xs font-normal text-muted-foreground">
                {t('sensors.onboard.policy.text')}
              </span>
            </span>
            <ChevronDown className="h-4 w-4 shrink-0" aria-hidden />
          </CollapsibleTrigger>
          <CollapsibleContent className="border-t p-3">
            <Snippet
              text={data.policy}
              label={t('sensors.onboard.policy.title')}
              file="sensor-policy.yaml"
            />
          </CollapsibleContent>
        </Collapsible>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Create a pairing code first
// ---------------------------------------------------------------------------

/**
 * Poll the approved sensor until its first heartbeat. Module scope: SWR
 * restarts its timer whenever `refreshInterval` changes identity, and this
 * panel re-renders every second (the code's countdown).
 */
function sensorSeenInterval(s?: Sensor): number {
  return s?.last_seen_at ? 0 : FIRST_HEARTBEAT_POLL_MS
}

function CodeFirst({
  platform,
  onOpenSensor,
  onDone,
}: {
  platform: OnboardingPlatform
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

  if (!created) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-muted-foreground">{t('sensors.onboard.code.intro')}</p>
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        <Button onClick={() => void create()} disabled={busy}>
          {busy && <Loader2 className="h-4 w-4 animate-spin" />}
          {t('sensors.onboard.code.create')}
        </Button>
      </div>
    )
  }

  const code = formatPairingCode(created.code ?? '')
  const left = secondsUntil(view?.expires_at, now)

  return (
    <div className="space-y-4">
      {stage === 'waiting' || stage === 'ended' ? (
        <>
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
          <InstallCommands platform={platform} code={code} />
        </>
      ) : null}

      <OnboardingStatus stage={stage} />

      {stage === 'waiting' && (
        <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
          {pollError ? (
            <span role="alert" className="text-destructive">
              {pairingErrorMessage(pollError, t('sensors.onboard.code.pollFailed'), t)}
            </span>
          ) : (
            <span />
          )}
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
              ? t('sensors.pair.rejected')
              : t('sensors.onboard.code.ended')}
          </span>
          <Button variant="outline" size="sm" onClick={() => void create()} disabled={busy}>
            {t('sensors.pair.getNewCode')}
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
// Pair interactively
// ---------------------------------------------------------------------------

function Interactive({ platform, onDone }: { platform: OnboardingPlatform; onDone?: () => void }) {
  const { t } = useTranslation()
  const [approved, setApproved] = useState<SensorPairingView | null>(null)
  if (approved) {
    return (
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3 text-sm">
        <span aria-live="polite">{t('sensors.onboard.approvedWaiting')}</span>
        {onDone && (
          <Button size="sm" onClick={onDone}>
            {t('sensors.pair.done')}
          </Button>
        )}
      </div>
    )
  }
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">{t('sensors.onboard.interactive.intro')}</p>
      <InstallCommands platform={platform} code={null} />
      <div className="space-y-2">
        <h4 className="text-sm font-medium">{t('sensors.onboard.interactive.enter')}</h4>
        <EnterCodePanel onApproved={setApproved} onClose={() => onDone?.()} />
      </div>
    </div>
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
