/**
 * Scan Wizard Stepper
 *
 * A map of the wizard, not a gate: every step is a button, so a person can
 * look at any step before the earlier ones are complete. Each step shows its
 * state: a check when complete, a warning with the number of problems, or its
 * number when not visited yet. Desktop: every step with its label. Phone:
 * "Step N of M: Name" and a progress bar; tapping it opens the step list.
 * Design: research/418.
 */

'use client'

import { useState } from 'react'
import { cn } from '@/lib/utils'
import { AlertTriangle, Check, ChevronDown } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import type { StepStatus } from '../../lib/wizard-validity'

export type ScanWizardStep = 'basic' | 'targets' | 'options' | 'schedule' | 'review'

interface ScanStepperProps {
  currentStep: ScanWizardStep
  onStepClick?: (step: ScanWizardStep) => void
  /** The steps shown, in order (New adds Review). */
  steps?: ScanWizardStep[]
  /** Each step's state; a step without one shows its number. */
  status?: Partial<Record<ScanWizardStep, StepStatus>>
  className?: string
}

const LABEL_KEYS: Record<ScanWizardStep, string> = {
  basic: 'scans.step.what',
  targets: 'scans.step.targets',
  options: 'scans.step.options',
  schedule: 'scans.step.schedule',
  review: 'scans.step.review',
}

export function stepLabelKey(step: ScanWizardStep): string {
  return LABEL_KEYS[step]
}

const DEFAULT_STEPS: ScanWizardStep[] = ['basic', 'targets', 'options', 'schedule']

function StepMark({
  index,
  status,
  current,
}: {
  index: number
  status?: StepStatus
  current: boolean
}) {
  if (status?.state === 'invalid') {
    return (
      <span
        className={cn(
          'flex h-5 min-w-5 shrink-0 items-center justify-center gap-0.5 rounded-full px-1 text-xs',
          current ? 'bg-primary-foreground/20' : 'bg-warning/15 text-foreground'
        )}
      >
        <AlertTriangle className={cn('h-3 w-3', !current && 'text-warning')} aria-hidden />
        {status.count}
      </span>
    )
  }
  if (status?.state === 'valid') {
    return (
      <span
        className={cn(
          'flex h-5 w-5 shrink-0 items-center justify-center rounded-full',
          current ? 'bg-primary-foreground/20' : 'bg-primary/10'
        )}
      >
        <Check className="h-3 w-3" aria-hidden />
      </span>
    )
  }
  return (
    <span
      className={cn(
        'flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-xs',
        current ? 'bg-primary-foreground/20' : 'bg-muted-foreground/20'
      )}
    >
      {index + 1}
    </span>
  )
}

export function ScanStepper({
  currentStep,
  onStepClick,
  steps = DEFAULT_STEPS,
  status = {},
  className,
}: ScanStepperProps) {
  const { t } = useTranslation()
  const STEPS = steps.map((id) => ({ id, label: t(LABEL_KEYS[id]) }))
  const currentIndex = STEPS.findIndex((s) => s.id === currentStep)

  const [listOpen, setListOpen] = useState(false)
  const current = STEPS[currentIndex]
  const progress = STEPS.length > 0 ? ((currentIndex + 1) / STEPS.length) * 100 : 0
  // The accessible name says the state too ("Targets, 2 problems").
  const nameOf = (step: { id: ScanWizardStep; label: string }) => {
    const s = status[step.id]
    if (s?.state === 'invalid')
      return t('scans.wizard.stepProblems', undefined, { name: step.label, count: s.count })
    if (s?.state === 'valid') return t('scans.wizard.stepValid', undefined, { name: step.label })
    return step.label
  }
  const currentStatus = status[currentStep]

  return (
    <nav
      className={cn('min-w-0 px-4 py-3 sm:px-6', className)}
      aria-label={t('scans.wizard.steps')}
    >
      {/* Phone */}
      <div className="sm:hidden">
        <button
          type="button"
          className="flex min-h-11 w-full min-w-0 items-center gap-2 text-start"
          aria-expanded={listOpen}
          aria-controls="scan-stepper-list"
          onClick={() => setListOpen((o) => !o)}
          data-testid="stepper-phone"
        >
          <span className="min-w-0 flex-1 truncate text-sm font-medium">
            {t('scans.step.ofTotal', undefined, {
              n: currentIndex + 1,
              total: STEPS.length,
              name: current?.label ?? '',
            })}
          </span>
          {currentStatus?.state === 'invalid' && (
            <AlertTriangle className="h-4 w-4 shrink-0 text-warning" aria-hidden />
          )}
          <ChevronDown
            className={cn(
              'h-4 w-4 shrink-0 text-muted-foreground transition-transform',
              listOpen && 'rotate-180'
            )}
            aria-hidden
          />
        </button>
        <div
          className="h-1 w-full overflow-hidden rounded-full bg-muted"
          role="progressbar"
          aria-valuemin={1}
          aria-valuemax={STEPS.length}
          aria-valuenow={currentIndex + 1}
          aria-label={t('scans.step.progress')}
        >
          <div className="h-full rounded-full bg-signal" style={{ width: `${progress}%` }} />
        </div>
        {listOpen && (
          <ol id="scan-stepper-list" className="mt-2 divide-y text-sm">
            {STEPS.map((step, index) => (
              <li key={step.id}>
                <button
                  type="button"
                  onClick={() => {
                    setListOpen(false)
                    onStepClick?.(step.id)
                  }}
                  aria-current={index === currentIndex ? 'step' : undefined}
                  aria-label={nameOf(step)}
                  data-state={status[step.id]?.state ?? 'idle'}
                  className={cn(
                    'flex min-h-11 w-full items-center gap-2 text-start',
                    index === currentIndex && 'font-medium'
                  )}
                >
                  <StepMark index={index} status={status[step.id]} current={false} />
                  {step.label}
                </button>
              </li>
            ))}
          </ol>
        )}
      </div>

      {/* Desktop */}
      <ol className="hidden min-w-0 items-center justify-between sm:flex">
        {STEPS.map((step, index) => {
          const isCurrent = index === currentIndex
          return (
            <li key={step.id} className="flex flex-1 items-center last:flex-none">
              <button
                type="button"
                onClick={() => onStepClick?.(step.id)}
                aria-current={isCurrent ? 'step' : undefined}
                aria-label={nameOf(step)}
                data-state={status[step.id]?.state ?? 'idle'}
                className={cn(
                  'flex min-h-9 items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-1.5 text-xs font-medium transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-hidden',
                  isCurrent
                    ? 'bg-primary text-primary-foreground'
                    : 'text-foreground hover:bg-muted'
                )}
              >
                <StepMark index={index} status={status[step.id]} current={isCurrent} />
                <span>{step.label}</span>
              </button>

              {index < STEPS.length - 1 && (
                <div className="mx-2 h-px min-w-[12px] flex-1 bg-border" aria-hidden />
              )}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}
