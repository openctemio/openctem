/**
 * Scan Wizard Stepper
 *
 * Desktop: every step with its label. Phone: "Step N of M: Name" and a
 * progress bar; tapping it opens the step list, where finished steps can be
 * revisited.
 */

'use client'

import { useState } from 'react'
import { cn } from '@/lib/utils'
import { Check, ChevronDown } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'

export type ScanWizardStep = 'basic' | 'targets' | 'options' | 'schedule' | 'review'

interface ScanStepperProps {
  currentStep: ScanWizardStep
  onStepClick?: (step: ScanWizardStep) => void
  /** The steps shown, in order (New adds Review). */
  steps?: ScanWizardStep[]
  className?: string
}

const LABEL_KEYS: Record<ScanWizardStep, string> = {
  basic: 'scans.step.what',
  targets: 'scans.step.targets',
  options: 'scans.step.options',
  schedule: 'scans.step.schedule',
  review: 'scans.step.review',
}

const DEFAULT_STEPS: ScanWizardStep[] = ['basic', 'targets', 'options', 'schedule']

export function ScanStepper({
  currentStep,
  onStepClick,
  steps = DEFAULT_STEPS,
  className,
}: ScanStepperProps) {
  const { t } = useTranslation()
  const STEPS = steps.map((id) => ({ id, label: t(LABEL_KEYS[id]) }))
  const currentIndex = STEPS.findIndex((s) => s.id === currentStep)

  const [listOpen, setListOpen] = useState(false)
  const current = STEPS[currentIndex]
  const progress = STEPS.length > 0 ? ((currentIndex + 1) / STEPS.length) * 100 : 0

  return (
    <div className={cn('min-w-0 px-4 py-3 sm:px-6', className)}>
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
            {STEPS.map((step, index) => {
              const done = index < currentIndex
              return (
                <li key={step.id}>
                  <button
                    type="button"
                    disabled={!done}
                    onClick={() => {
                      setListOpen(false)
                      onStepClick?.(step.id)
                    }}
                    aria-current={index === currentIndex ? 'step' : undefined}
                    className={cn(
                      'flex min-h-11 w-full items-center gap-2 text-start',
                      index === currentIndex && 'font-medium',
                      index > currentIndex && 'text-muted-foreground'
                    )}
                  >
                    <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-muted text-xs">
                      {done ? <Check className="h-3 w-3" aria-hidden /> : index + 1}
                    </span>
                    {step.label}
                  </button>
                </li>
              )
            })}
          </ol>
        )}
      </div>

      {/* Desktop */}
      <div className="hidden min-w-0 items-center justify-between sm:flex">
        {STEPS.map((step, index) => {
          const isCompleted = index < currentIndex
          const isCurrent = index === currentIndex
          const isPending = index > currentIndex

          return (
            <div key={step.id} className="flex flex-1 items-center last:flex-none">
              <button
                type="button"
                onClick={() => isCompleted && onStepClick?.(step.id)}
                disabled={!isCompleted}
                aria-current={isCurrent ? 'step' : undefined}
                className={cn(
                  'flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-1.5 text-xs font-medium transition-colors',
                  isCompleted && 'cursor-pointer bg-primary/10 text-primary hover:bg-primary/20',
                  isCurrent && 'bg-primary text-primary-foreground',
                  isPending && 'bg-muted/50 text-muted-foreground'
                )}
              >
                {isCompleted ? (
                  <Check className="h-3.5 w-3.5" aria-hidden />
                ) : (
                  <span
                    className={cn(
                      'flex h-5 w-5 items-center justify-center rounded-full text-xs',
                      isCurrent && 'bg-primary-foreground/20',
                      isPending && 'bg-muted-foreground/20'
                    )}
                  >
                    {index + 1}
                  </span>
                )}
                <span>{step.label}</span>
              </button>

              {index < STEPS.length - 1 && (
                <div
                  className={cn(
                    'mx-2 h-0.5 min-w-[12px] flex-1',
                    index < currentIndex ? 'bg-primary' : 'bg-muted'
                  )}
                />
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
