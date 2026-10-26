'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { Check, KeyRound, Loader2, RadioTower } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { OneTimeSecretField } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { assignSensorToZone, useScanZones } from '@/lib/api/scan-zone-hooks'
import { invalidateSensorsCache, useCreateSensor, useSensor } from '@/lib/api/sensor-hooks'
import type { Sensor, SensorType } from '@/lib/api/sensor-types'
import { Permission, useHasPermission } from '@/lib/permissions'
import { cn } from '@/lib/utils'

import { SensorInstallSnippets } from './sensor-install-snippets'
import { SensorFirstReport } from './sensor-tool-review'
import { hasReportedTools } from '../lib/capabilities'
import type { Tr } from '../lib/format'

/** What the sensor does, mapped to the API's legacy type and execution mode. */
export type InstallRole = 'scanner' | 'collector'

/**
 * The roles. None of them sets tools: which tools a sensor has is known only
 * to the sensor, which reports them on its first heartbeat (step 3).
 */
export const INSTALL_ROLES: Record<
  InstallRole,
  { label: string; hint: string; type: SensorType; mode: 'daemon' | 'standalone' }
> = {
  scanner: {
    label: 'Scanner',
    hint: 'Runs the scans the platform sends it, all the time',
    type: 'worker',
    mode: 'daemon',
  },
  collector: {
    label: 'Collector',
    hint: 'Collects assets and telemetry, no scanning',
    type: 'collector',
    mode: 'daemon',
  },
}

/** How often the flow checks for the first heartbeat. */
export const FIRST_HEARTBEAT_POLL_MS = 5000

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$/

export type InstallStep = 'name' | 'install' | 'connected'
type Step = InstallStep

const STEPS = [
  {
    key: 'name',
    title: 'Name it and pick a role',
    text: 'The name shows on this page. A zone is optional.',
  },
  {
    key: 'install',
    title: 'Run the command on the host',
    text: 'docker run, Compose, Kubernetes or Helm. The key is already in it.',
  },
  {
    key: 'review',
    title: 'Review what it reported',
    text: 'When its first heartbeat arrives: its host, version and tools.',
  },
] as const

/** The step the flow is on, 0-based, and its title ("Step 2 of 3: Run the command on the host"). */
export function installStepIndex(step: InstallStep): number {
  return step === 'name' ? 0 : step === 'connected' ? 2 : 1
}

export function installStepLabel(step: InstallStep, tr?: Tr): string {
  const i = installStepIndex(step)
  if (!tr) return `Step ${i + 1} of ${STEPS.length}: ${STEPS[i].title}`
  return tr('sensors.installFlow.stepOf', undefined, {
    n: i + 1,
    total: STEPS.length,
    title: tr(`sensors.installFlow.step.${STEPS[i].key}.title`, STEPS[i].title),
  })
}

function StepList({ step }: { step: Step }) {
  const { t } = useTranslation()
  const steps = STEPS
  const doneIdx = installStepIndex(step)
  return (
    <ol className="space-y-4" aria-label={t('sensors.installFlow.steps')}>
      {steps.map((s, i) => {
        const done = i < doneIdx
        const current = i === doneIdx
        return (
          <li key={s.key} className="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-3">
            <span
              aria-hidden
              className={cn(
                'grid size-7 place-items-center rounded-full border text-xs font-semibold',
                done && 'border-success bg-success text-background',
                current && 'border-primary bg-primary text-primary-foreground',
                !done && !current && 'text-muted-foreground'
              )}
            >
              {done ? <Check className="h-3.5 w-3.5" /> : i + 1}
            </span>
            <span>
              <span className="block text-sm font-semibold">
                {t(`sensors.installFlow.step.${s.key}.title`, s.title)}
                {done && <span className="sr-only"> ({t('sensors.installFlow.done')})</span>}
              </span>
              <span className="block text-sm text-muted-foreground">
                {t(`sensors.installFlow.step.${s.key}.text`, s.text)}
              </span>
            </span>
          </li>
        )
      })}
    </ol>
  )
}

/**
 * Poll until the sensor has sent its first heartbeat and its tool list. A
 * module-level function: SWR restarts its timer whenever the interval
 * changes identity, and the page re-renders every second.
 */
function firstHeartbeatInterval(latest?: Sensor): number {
  return latest?.last_seen_at && hasReportedTools(latest) ? 0 : FIRST_HEARTBEAT_POLL_MS
}

/**
 * Watches the new sensor until its first heartbeat arrives, then shows what
 * it reported. It keeps checking while the sensor's tool list has not
 * arrived (it can lag the first heartbeat), so the review fills in by itself.
 */
function FirstHeartbeat({
  sensorId,
  onConnected,
  onOpen,
  onDone,
  children,
}: {
  sensorId: string
  onConnected: () => void
  onOpen?: (sensor: Sensor) => void
  onDone?: () => void
  /** Shown with the review, above its buttons (the zone picker). */
  children?: React.ReactNode
}) {
  const { t } = useTranslation()
  const { data: s } = useSensor(sensorId, { refreshInterval: firstHeartbeatInterval })
  const connected = !!s?.last_seen_at
  const notified = useRef(false)
  useEffect(() => {
    if (connected && !notified.current) {
      notified.current = true
      onConnected()
    }
  }, [connected, onConnected])

  if (s && connected) {
    return (
      <SensorFirstReport sensor={s} onOpen={onOpen} onDone={onDone}>
        {children}
      </SensorFirstReport>
    )
  }
  return (
    <div
      className="flex items-start gap-3 rounded-lg border border-dashed p-3 text-sm"
      role="status"
    >
      <Loader2
        className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-info motion-reduce:animate-none"
        aria-hidden
      />
      <div>
        <p className="font-medium">{t('sensors.installFlow.waiting')}</p>
        <p className="text-muted-foreground">
          {t('sensors.installFlow.waitingHelp', undefined, {
            seconds: FIRST_HEARTBEAT_POLL_MS / 1000,
          })}
        </p>
      </div>
    </div>
  )
}

export interface SensorInstallFlowProps {
  /** Called with the sensor once it is created. */
  onCreated?: (sensor: Sensor) => void
  /** "Open sensor" after the first heartbeat. */
  onOpen?: (sensor: Sensor) => void
  /** "Done" after reviewing what the sensor reported (the dialog closes). */
  onDone?: () => void
  /** Rendered beside the steps: "Install your first sensor" on an empty page. */
  title?: string
  /**
   * `card` (default): a self-contained card with its own title, for a page.
   * `dialog`: no title or frame (the dialog's header bar has them); the form
   * pane is an inset panel, so nothing tinted reaches the dialog's edge.
   */
  variant?: 'card' | 'dialog'
  /** Called when the flow moves to another step (the dialog shows it in its header). */
  onStepChange?: (step: InstallStep) => void
  className?: string
}

/**
 * Install a sensor (mockup frame C): name and role, then the commands with the
 * key already in them (shown once), a live wait for the first heartbeat, then
 * what the sensor reported. Creating a sensor issues a credential, so this is for admins
 * (sensors:write).
 */
export function SensorInstallFlow({
  onCreated,
  onOpen,
  onDone,
  title,
  variant = 'card',
  onStepChange,
  className,
}: SensorInstallFlowProps) {
  const [step, setStepState] = useState<Step>('name')
  const stepChange = useRef(onStepChange)
  useEffect(() => {
    stepChange.current = onStepChange
  })
  const setStep = (next: Step) => {
    setStepState(next)
    stepChange.current?.(next)
  }
  const [name, setName] = useState('')
  const [role, setRole] = useState<InstallRole>('scanner')
  const [zoneId, setZoneId] = useState<string>('')
  const [created, setCreated] = useState<{ sensor: Sensor; apiKey: string } | null>(null)
  const [assigning, setAssigning] = useState(false)
  // Trust is an explicit choice for a collector only, off by default.
  const [trustCollector, setTrustCollector] = useState(false)
  const { t } = useTranslation()
  const heading = title ?? t('sensors.installFlow.title')

  const { trigger: createSensor, isMutating } = useCreateSensor()
  const canTrust = useHasPermission(Permission.SensorsGrantWiden)
  const canWriteZones = useHasPermission(Permission.ScanZonesWrite)
  const canReadZones = useHasPermission(Permission.ScanZonesRead)
  const { data: zonesData } = useScanZones(canReadZones)
  const zones = zonesData?.data ?? []

  const nameError =
    name.trim() === ''
      ? null
      : NAME_RE.test(name.trim())
        ? null
        : t('sensors.installFlow.nameInvalid')

  const assignZone = async (sensorId: string, zone: string) => {
    if (!zone || !canWriteZones) return
    setAssigning(true)
    try {
      await assignSensorToZone(zone, sensorId)
      toast.success(t('sensors.installFlow.zoneAssigned'))
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.installFlow.zoneAssignFailed')))
    } finally {
      setAssigning(false)
    }
  }

  const handleCreate = async () => {
    const trimmed = name.trim()
    if (!trimmed || nameError) return
    const r = INSTALL_ROLES[role]
    try {
      // No tools or capabilities: the sensor reports what it has on its
      // first heartbeat, and jobs use every installed tool it reports (the
      // sensor grant narrows them).
      const trusted = role === 'collector' && canTrust && trustCollector
      const res = await createSensor({
        name: trimmed,
        type: r.type,
        execution_mode: r.mode,
        ...(trusted ? { trusted: true } : {}),
      })
      if (!res?.api_key || !res.sensor) throw new Error(t('sensors.installFlow.noKey'))
      if (trusted && !res.trusted) {
        toast.warning(
          t(
            'sensors.install.trustCollector.notApplied',
            "The collector was created, but trusting it failed. It stays untrusted until it is promoted on the sensor's Grant."
          )
        )
      }
      setCreated({ sensor: res.sensor, apiKey: res.api_key })
      setStep('install')
      onCreated?.(res.sensor)
      await invalidateSensorsCache()
      if (zoneId) await assignZone(res.sensor.id, zoneId)
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.installFlow.createFailed')))
    }
  }

  // Stable for FirstHeartbeat's effect; moves to the review once.
  const handleConnected = useCallback(() => {
    setStepState('connected')
    stepChange.current?.('connected')
  }, [])

  const zoneSelect = canReadZones && zones.length > 0 && (
    <div className="space-y-1.5">
      <Label htmlFor="install-zone">
        {t('sensors.installFlow.zone')}{' '}
        <span className="font-normal text-muted-foreground">({t('sensors.edit.optional')})</span>
      </Label>
      <Select
        value={zoneId || 'none'}
        onValueChange={async (v) => {
          const next = v === 'none' ? '' : v
          setZoneId(next)
          if (created) await assignZone(created.sensor.id, next)
        }}
        disabled={!canWriteZones || assigning}
      >
        <SelectTrigger id="install-zone" aria-label={t('sensors.installFlow.zone')}>
          <SelectValue placeholder={t('sensors.installFlow.noZone')} />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="none">{t('sensors.installFlow.noZone')}</SelectItem>
          {zones.map((z) => (
            <SelectItem key={z.id} value={z.id}>
              {z.name}
              {z.ranges.length ? `, ${z.ranges[0]}` : ''}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )

  const inDialog = variant === 'dialog'
  const intro = (
    <p className="max-w-prose text-sm text-muted-foreground">{t('sensors.installFlow.intro')}</p>
  )

  return (
    <div
      className={cn(
        'grid min-w-0 md:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]',
        inDialog ? 'gap-6 p-4 sm:p-6' : 'overflow-hidden rounded-xl border bg-card',
        className
      )}
    >
      <div
        className={cn('space-y-5', inDialog ? 'md:py-1' : 'border-b p-6 md:border-e md:border-b-0')}
      >
        {inDialog ? (
          intro
        ) : (
          <>
            <span className="grid size-10 place-items-center rounded-lg bg-muted" aria-hidden>
              <RadioTower className="h-5 w-5" />
            </span>
            <div className="space-y-2">
              <h2 className="text-xl font-semibold">{heading}</h2>
              {intro}
            </div>
          </>
        )}
        {/* On a phone the dialog's header says the step; the list would push the form below the fold. */}
        <div className={cn(inDialog && 'hidden md:block')}>
          <StepList step={step} />
        </div>
      </div>

      <div
        className={cn(
          'min-w-0 space-y-4 bg-muted/30',
          inDialog ? 'rounded-lg border p-4 sm:p-5' : 'p-6'
        )}
        data-slot="install-form-pane"
      >
        {step === 'name' ? (
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault()
              void handleCreate()
            }}
          >
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="install-name">{t('sensors.installFlow.name')}</Label>
                <Input
                  id="install-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="dmz-scanner-01"
                  autoComplete="off"
                  aria-invalid={!!nameError}
                  aria-describedby={nameError ? 'install-name-error' : undefined}
                />
                {nameError && (
                  <p id="install-name-error" className="text-xs text-destructive">
                    {nameError}
                  </p>
                )}
              </div>
              {zoneSelect}
            </div>

            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">{t('sensors.installFlow.role')}</legend>
              <div
                className="grid gap-2 sm:grid-cols-2"
                role="radiogroup"
                aria-label={t('sensors.installFlow.role')}
              >
                {(Object.keys(INSTALL_ROLES) as InstallRole[]).map((r) => (
                  <button
                    key={r}
                    type="button"
                    role="radio"
                    aria-checked={role === r}
                    onClick={() => setRole(r)}
                    className={cn(
                      'rounded-lg border bg-background p-3 text-start transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                      role === r ? 'border-primary ring-1 ring-primary' : 'hover:bg-accent'
                    )}
                  >
                    <span className="block text-sm font-medium">
                      {t(`sensors.installFlow.roles.${r}.label`, INSTALL_ROLES[r].label)}
                    </span>
                    <span className="block text-xs text-muted-foreground">
                      {t(`sensors.installFlow.roles.${r}.hint`, INSTALL_ROLES[r].hint)}
                    </span>
                  </button>
                ))}
              </div>
            </fieldset>

            {role !== 'collector' && (
              <p className="text-xs text-muted-foreground">
                {t('sensors.installFlow.scannerNote')}
              </p>
            )}

            {role === 'collector' && (
              <div className="flex items-start gap-2 rounded-lg border bg-background p-3">
                <Checkbox
                  id="install-trust-collector"
                  checked={canTrust && trustCollector}
                  onCheckedChange={(c) => setTrustCollector(c === true)}
                  disabled={!canTrust}
                  aria-describedby="install-trust-collector-help"
                  className="mt-0.5"
                />
                <div className="space-y-1">
                  <Label htmlFor="install-trust-collector" className="leading-snug">
                    {t(
                      'sensors.install.trustCollector.label',
                      'Trust this collector to push asset reports'
                    )}
                  </Label>
                  <p id="install-trust-collector-help" className="text-xs text-muted-foreground">
                    {canTrust
                      ? t(
                          'sensors.install.trustCollector.help',
                          'A new collector starts untrusted, and the platform refuses every report it sends until it is trusted.'
                        )
                      : t(
                          'sensors.install.trustCollector.noPermission',
                          'Only an administrator who may widen sensor grants can trust a collector.'
                        )}
                  </p>
                </div>
              </div>
            )}

            <div className="flex justify-end">
              <Button type="submit" disabled={!name.trim() || !!nameError || isMutating}>
                {isMutating && <Loader2 className="h-4 w-4 animate-spin" />}
                {t('sensors.installFlow.create')}
              </Button>
            </div>
          </form>
        ) : created ? (
          <>
            {step === 'install' && (
              <>
                <div className="flex gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-sm">
                  <KeyRound className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
                  <div className="min-w-0 space-y-2">
                    <p>
                      <span className="font-medium">{t('sensors.installFlow.copyKeyLead')}</span>{' '}
                      {t('sensors.installFlow.copyKeyBody')}
                    </p>
                    <OneTimeSecretField
                      label={t('sensors.installFlow.apiKey')}
                      noun={t('sensors.installFlow.apiKey')}
                      value={created.apiKey}
                    />
                  </div>
                </div>
                <SensorInstallSnippets sensorId={created.sensor.id} apiKey={created.apiKey} />
              </>
            )}
            <FirstHeartbeat
              sensorId={created.sensor.id}
              onConnected={handleConnected}
              onOpen={onOpen}
              onDone={onDone}
            >
              {step === 'connected' && zoneSelect}
            </FirstHeartbeat>
            {step !== 'connected' && zoneSelect}
          </>
        ) : null}
      </div>
    </div>
  )
}
