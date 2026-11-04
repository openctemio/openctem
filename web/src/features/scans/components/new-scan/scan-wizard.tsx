'use client'

/**
 * The scan wizard shell, one for New scan and Edit scan: the stepper (every
 * step can be opened at any time, each showing whether it is complete), the
 * current step beside the live summary, and one footer row (Back, Next, the
 * primary action). Nothing stops a person from moving: problems show on the
 * steps they left, and the primary action stays disabled until every step is
 * valid, with the first problem named under it as a link to its step.
 * Ctrl/Cmd+Enter runs the primary action when it can, and otherwise goes to
 * the first problem. Moving to a step puts focus on its heading, so a screen
 * reader says where the person is; going to a problem focuses its field.
 * Design: research/418.
 */

import { useCallback, useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { ChevronRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useTranslation } from '@/context/i18n-provider'
import { ScanStepper, stepLabelKey, type ScanWizardStep } from './scan-stepper'
import { WizardFooter } from './wizard-chrome'
import { ScanSummaryBar } from './scan-summary'
import { firstIssue, stepStatuses, type StepIssues } from '../../lib/wizard-validity'

export interface ScanWizardProps {
  open: boolean
  /** The header X, Escape or a click outside (ignored while saving). */
  onRequestClose: () => void
  title: string
  description?: string
  steps: ScanWizardStep[]
  step: ScanWizardStep
  onStepChange: (step: ScanWizardStep) => void
  issues: StepIssues
  /** A create or save was attempted: every step shows its problems. */
  attempted: boolean
  /** Steps the person has left (they show their problems). */
  seen: ReadonlySet<ScanWizardStep>
  /** The summary, rendered beside the step (desktop) and in the bar (phone). */
  summary: ReactNode
  /** One line for the phone bar. */
  summaryLine: string
  /** Above the step (a restored draft, a refusal from the server). */
  banner?: ReactNode
  /** The current step. */
  children: ReactNode
  /** The primary action(s), shown on the last step, or on every step with `submitOnEveryStep`. */
  primary: ReactNode
  submitOnEveryStep?: boolean
  /** Every step is valid and the primary action may run. */
  canSubmit: boolean
  /** What Ctrl/Cmd+Enter runs when canSubmit. */
  onSubmit: () => void
  /** A note under the footer that replaces the first-problem link (why the action is disabled). */
  note?: ReactNode
  noteTone?: 'muted' | 'destructive'
  isLoading?: boolean
  /** Rendered after the dialog (the discard prompt). */
  after?: ReactNode
}

export function ScanWizard({
  open,
  onRequestClose,
  title,
  description,
  steps,
  step,
  onStepChange,
  issues,
  attempted,
  seen,
  summary,
  summaryLine,
  banner,
  children,
  primary,
  submitOnEveryStep = false,
  canSubmit,
  onSubmit,
  note,
  noteTone,
  isLoading,
  after,
}: ScanWizardProps) {
  const { t } = useTranslation()
  const headingRef = useRef<HTMLHeadingElement>(null)
  const bodyRef = useRef<HTMLDivElement>(null)
  // What to focus after the next step change: the heading, or the first
  // field marked invalid (going to a problem).
  const [focusTarget, setFocusTarget] = useState<'heading' | 'problem' | null>(null)

  const index = steps.indexOf(step)
  const isFirst = index <= 0
  const isLast = index === steps.length - 1
  const status = stepStatuses(issues, steps, seen, attempted)
  const problem = firstIssue(issues, steps)

  useEffect(() => {
    if (!focusTarget) return
    const id = requestAnimationFrame(() => {
      const field =
        focusTarget === 'problem'
          ? bodyRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')
          : null
      ;(field ?? headingRef.current)?.focus()
      setFocusTarget(null)
    })
    return () => cancelAnimationFrame(id)
  }, [focusTarget, step])

  const go = (next: ScanWizardStep, focus: 'heading' | 'problem' = 'heading') => {
    if (next !== step) onStepChange(next)
    setFocusTarget(focus)
  }
  const goToProblem = () => go(problem?.step ?? steps[steps.length - 1], 'problem')

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'Enter' || !(e.metaKey || e.ctrlKey) || e.defaultPrevented) return
    e.preventDefault()
    if (isLoading) return
    if (canSubmit) onSubmit()
    else goToProblem()
  }

  const showPrimary = isLast || submitOnEveryStep
  const problemNote =
    showPrimary && problem ? (
      <span>
        {problem.message}{' '}
        <button
          type="button"
          className="font-medium text-signal-text underline-offset-2 hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-hidden"
          onClick={goToProblem}
          data-testid="wizard-fix-link"
        >
          {t('scans.wizard.goTo', undefined, { name: t(stepLabelKey(problem.step)) })}
        </button>
      </span>
    ) : undefined
  const footerNote = note ?? problemNote

  return (
    <Dialog open={open} onOpenChange={(next) => !next && !isLoading && onRequestClose()}>
      <DialogContent size="full" onKeyDown={onKeyDown} data-testid="scan-wizard">
        <DialogHeader className="pb-0">
          <DialogTitle>{title}</DialogTitle>
          {description && (
            <DialogDescription className="max-sm:sr-only">{description}</DialogDescription>
          )}
          <ScanStepper
            className="px-0 pt-1 pb-2 sm:px-0"
            currentStep={step}
            onStepClick={(s) => go(s)}
            steps={steps}
            status={status}
          />
        </DialogHeader>

        <DialogBody className="px-0 py-0 sm:px-0" ref={bodyRef}>
          <div className="grid min-h-full min-w-0 lg:grid-cols-[minmax(0,1fr)_20rem]">
            <div className="min-w-0">
              <h3
                ref={headingRef}
                tabIndex={-1}
                className="sr-only"
                data-testid="wizard-step-heading"
              >
                {t('scans.step.ofTotal', undefined, {
                  n: index + 1,
                  total: steps.length,
                  name: t(stepLabelKey(step)),
                })}
              </h3>
              {banner}
              {children}
            </div>
            <aside
              className="hidden min-w-0 border-s bg-muted/30 lg:block"
              aria-label={t('scans.summaryPanel.title')}
            >
              <div className="sticky top-0 space-y-3 p-4">
                <h3 className="text-sm font-semibold">{t('scans.summaryPanel.title')}</h3>
                {summary}
              </div>
            </aside>
          </div>
        </DialogBody>

        <WizardFooter
          before={<ScanSummaryBar line={summaryLine}>{summary}</ScanSummaryBar>}
          onBack={isFirst ? undefined : () => go(steps[index - 1])}
          disabled={isLoading}
          noteId="wizard-note"
          noteTone={note ? noteTone : 'muted'}
          note={footerNote}
        >
          {!isLast && (
            <Button
              type="button"
              variant={submitOnEveryStep ? 'outline' : 'default'}
              onClick={() => go(steps[index + 1])}
              disabled={isLoading}
              data-testid="wizard-next"
            >
              {t('scans.common.next')}
              <ChevronRight className="ms-1 h-4 w-4" aria-hidden />
            </Button>
          )}
          {showPrimary && primary}
        </WizardFooter>
      </DialogContent>
      {after}
    </Dialog>
  )
}

/**
 * The navigation state a wizard dialog keeps: the current step, the steps
 * the person has left, and whether a create or save was attempted.
 */
export function useWizardSteps(first: ScanWizardStep) {
  const [step, setStep] = useState<ScanWizardStep>(first)
  const stepRef = useRef(first)
  const [seen, setSeen] = useState<ReadonlySet<ScanWizardStep>>(() => new Set())
  const [attempted, setAttempted] = useState(false)
  const changeStep = useCallback((next: ScanWizardStep) => {
    const left = stepRef.current
    setSeen((prev) => (prev.has(left) ? prev : new Set(prev).add(left)))
    stepRef.current = next
    setStep(next)
  }, [])
  const reset = useCallback(
    (to: ScanWizardStep = first) => {
      stepRef.current = to
      setStep(to)
      setSeen(new Set())
      setAttempted(false)
    },
    [first]
  )
  return { step, setStep: changeStep, seen, attempted, setAttempted, reset }
}
