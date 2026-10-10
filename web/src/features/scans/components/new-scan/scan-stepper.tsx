/**
 * Scan Wizard Stepper
 *
 * Visual step indicator for the new scan wizard
 */

import { cn } from '@/lib/utils'
import { Check } from 'lucide-react'

export type ScanWizardStep = 'basic' | 'targets' | 'options' | 'schedule' | 'review'

interface ScanStepperProps {
  currentStep: ScanWizardStep
  onStepClick?: (step: ScanWizardStep) => void
  /** The steps shown, in order (New adds Review). */
  steps?: ScanWizardStep[]
  className?: string
}

const LABELS: Record<ScanWizardStep, string> = {
  basic: 'What',
  targets: 'Targets',
  options: 'Options',
  schedule: 'Schedule',
  review: 'Review',
}

const DEFAULT_STEPS: ScanWizardStep[] = ['basic', 'targets', 'options', 'schedule']

export function ScanStepper({
  currentStep,
  onStepClick,
  steps = DEFAULT_STEPS,
  className,
}: ScanStepperProps) {
  const STEPS = steps.map((id) => ({ id, label: LABELS[id] }))
  const currentIndex = STEPS.findIndex((s) => s.id === currentStep)

  return (
    <div
      className={cn(
        'flex min-w-0 items-center justify-between overflow-x-auto px-4 py-3 sm:px-6',
        className
      )}
    >
      {STEPS.map((step, index) => {
        const isCompleted = index < currentIndex
        const isCurrent = index === currentIndex
        const isPending = index > currentIndex

        return (
          <div key={step.id} className="flex items-center flex-1 last:flex-none">
            {/* Step indicator */}
            <button
              type="button"
              onClick={() => isCompleted && onStepClick?.(step.id)}
              disabled={!isCompleted}
              className={cn(
                'flex items-center gap-1.5 rounded-full px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap',
                isCompleted && 'bg-primary/10 text-primary hover:bg-primary/20 cursor-pointer',
                isCurrent && 'bg-primary text-primary-foreground',
                isPending && 'text-muted-foreground bg-muted/50'
              )}
            >
              {isCompleted ? (
                <Check className="h-3.5 w-3.5" />
              ) : (
                <span
                  className={cn(
                    'flex h-4 w-4 items-center justify-center rounded-full text-[10px]',
                    isCurrent && 'bg-primary-foreground/20',
                    isPending && 'bg-muted-foreground/20'
                  )}
                >
                  {index + 1}
                </span>
              )}
              {/* Phone width: only the current step keeps its label, so the
                  four steps fit without widening the dialog. */}
              <span className={cn(!isCurrent && 'sr-only sm:not-sr-only')}>{step.label}</span>
            </button>

            {/* Connector line */}
            {index < STEPS.length - 1 && (
              <div
                className={cn(
                  'mx-1 h-0.5 min-w-[8px] flex-1 sm:mx-2 sm:min-w-[12px]',
                  index < currentIndex ? 'bg-primary' : 'bg-muted'
                )}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}
