'use client'

/**
 * The wizard frame every multi-step form shares: a dialog with a fixed
 * header, one step strip, the current step as the only part that scrolls,
 * and one footer row (a summary line at the start; Back, Next and the
 * primary action at the end).
 *
 * The step strip is a map, not a gate: every step is a button and can be
 * opened at any time. Each step shows its state in one fixed box (its
 * number, a check when complete, a warning when it has problems), so the
 * strip never moves when a state changes. The surface has one height for
 * every step, so the header, the strip and the footer stay where they are
 * while a person moves through the steps.
 *
 * The primary action stays disabled until `canSubmit`; the footer then names
 * the first problem as a link to its step. Ctrl/Cmd+Enter runs the primary
 * action when it can and goes to the first problem otherwise. Moving to a
 * step puts focus on its heading, so a screen reader says where the person
 * is; going to a problem focuses the first field marked invalid.
 */

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from 'react'
import { AlertTriangle, ArrowLeft, ArrowRight, Check, ChevronUp } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  type DialogSize,
} from '@/components/ui/dialog'
import { TAB_CLASS, TAB_STRIP_CLASS, useTabStripScroll } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export type WizardStepState = 'idle' | 'valid' | 'invalid'

export interface WizardStepStatus {
  state: WizardStepState
  /** Problems shown on the step (0 when valid or not shown yet). */
  count: number
}

export interface WizardStepDef<S extends string> {
  id: S
  label: string
}

/** The first problem of the form: its step and what to fix. */
export interface WizardProblem<S extends string> {
  step: S
  message: string
}

/**
 * One height for every step: the header, the strip and the footer never move
 * between steps. A full-height sheet on a phone (the kit caps it to the
 * visible screen), a fixed block capped to the screen from `sm`.
 */
const WIZARD_SURFACE_CLASS = 'h-dvh sm:h-[min(90dvh,52rem)]'

// ============================================================================
// Step strip
// ============================================================================

/** The state of a step in one fixed 20px box. */
function StepMark({ index, status }: { index: number; status?: WizardStepStatus }) {
  const box = 'relative flex size-5 shrink-0 items-center justify-center rounded-full'
  if (status?.state === 'invalid') {
    return (
      <span className={cn(box, 'bg-warning/15 text-foreground')} aria-hidden>
        <AlertTriangle className="size-3.5 text-warning" />
        {status.count > 1 && (
          <span className="absolute -end-2 -top-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-foreground px-1 text-cap-m text-background">
            {status.count}
          </span>
        )}
      </span>
    )
  }
  if (status?.state === 'valid') {
    return (
      <span className={cn(box, 'bg-foreground text-background')} aria-hidden>
        <Check className="size-3.5" />
      </span>
    )
  }
  return (
    <span className={cn(box, 'border border-input text-cap-m text-muted-foreground')} aria-hidden>
      {index + 1}
    </span>
  )
}

export interface WizardStepsProps<S extends string> {
  steps: readonly WizardStepDef<S>[]
  current: S
  onStepChange?: (step: S) => void
  /** Each step's state; a step without one shows its number. */
  status?: Partial<Record<S, WizardStepStatus>>
  /** The strip's accessible name (defaults to "Steps"). */
  label?: string
  className?: string
}

export function WizardSteps<S extends string>({
  steps,
  current,
  onStepChange,
  status = {},
  label,
  className,
}: WizardStepsProps<S>) {
  const { t } = useTranslation()
  const stripRef = useRef<HTMLOListElement>(null)
  useTabStripScroll(stripRef, steps.length)
  // The accessible name says the state too ("Targets, 2 problems").
  const nameOf = (step: WizardStepDef<S>) => {
    const s = status[step.id]
    if (s?.state === 'invalid')
      return t('common.wizard.stepProblems', undefined, { name: step.label, count: s.count })
    if (s?.state === 'valid') return t('common.wizard.stepValid', undefined, { name: step.label })
    return step.label
  }
  return (
    <nav
      className={cn('min-w-0 shrink-0', className)}
      aria-label={label ?? t('common.wizard.steps')}
      data-slot="wizard-steps"
    >
      <ol ref={stripRef} className={TAB_STRIP_CLASS}>
        {steps.map((step, index) => {
          const isCurrent = step.id === current
          return (
            <li key={step.id} className="flex shrink-0">
              <button
                type="button"
                onClick={() => onStepChange?.(step.id)}
                aria-current={isCurrent ? 'step' : undefined}
                aria-label={nameOf(step)}
                data-state={isCurrent ? 'active' : 'inactive'}
                data-status={status[step.id]?.state ?? 'idle'}
                className={TAB_CLASS}
              >
                <StepMark index={index} status={status[step.id]} />
                <span>{step.label}</span>
              </button>
            </li>
          )
        })}
      </ol>
    </nav>
  )
}

// ============================================================================
// Footer
// ============================================================================

export interface WizardSummary {
  /** The panel's name ("Summary"). */
  title: string
  /** One line, shown in the footer at every width. */
  line: string
  /** The whole summary, opened from the line. */
  content: ReactNode
}

export interface WizardFooterProps {
  /** Go one step back (hidden on the first step). */
  onBack?: () => void
  disabled?: boolean
  /** The step's actions, end side; the primary one last. */
  children: ReactNode
  /** Why the primary action is disabled, or a note about it. */
  note?: ReactNode
  noteId?: string
  noteTone?: 'muted' | 'destructive'
  summary?: WizardSummary
}

/**
 * The footer row: the summary line (it opens the whole summary above the
 * row) and the note at the start, the actions at the end. The actions sit on
 * the bottom line, so a note that appears never moves them. On a phone the
 * summary has its own line and the buttons share one row.
 */
export function WizardFooter({
  onBack,
  disabled,
  children,
  note,
  noteId,
  noteTone = 'muted',
  summary,
}: WizardFooterProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const panelId = useId()
  return (
    <div
      data-slot="wizard-footer"
      className="flex shrink-0 flex-col gap-2 border-t px-4 pt-3 pb-[max(1rem,env(safe-area-inset-bottom))] sm:px-6 sm:pb-4"
    >
      {summary && open && (
        <section
          id={panelId}
          aria-label={summary.title}
          className="max-h-[45dvh] overflow-y-auto overscroll-contain border-b pb-3"
          data-testid="summary-panel"
        >
          {summary.content}
        </section>
      )}
      <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-end sm:gap-3">
        <div className="flex min-w-0 flex-1 flex-col justify-center gap-1 sm:min-h-control">
          {summary && (
            <button
              type="button"
              className="flex min-w-0 items-center gap-1.5 rounded-sm text-start text-dense text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-hidden"
              aria-expanded={open}
              aria-controls={panelId}
              onClick={() => setOpen((o) => !o)}
              data-testid="summary-bar"
            >
              <span className="sr-only">{summary.title}: </span>
              <span className="min-w-0 truncate">{summary.line}</span>
              <ChevronUp
                className={cn('size-4 shrink-0 transition-transform', open && 'rotate-180')}
                aria-hidden
              />
            </button>
          )}
          {note && (
            <p
              id={noteId}
              className={cn(
                'min-w-0 text-dense',
                noteTone === 'destructive' ? 'text-destructive' : 'text-muted-foreground'
              )}
              data-testid="wizard-note"
            >
              {note}
            </p>
          )}
        </div>
        <div className="flex min-w-0 shrink-0 items-center justify-end gap-2 max-sm:[&>*]:min-w-0 max-sm:[&>*]:flex-1">
          {onBack && (
            <Button
              type="button"
              variant="ghost"
              onClick={onBack}
              disabled={disabled}
              data-testid="wizard-back"
            >
              <ArrowLeft aria-hidden />
              {t('common.wizard.back')}
            </Button>
          )}
          {children}
        </div>
      </div>
    </div>
  )
}

// ============================================================================
// Frame
// ============================================================================

export interface WizardFrameProps<S extends string> {
  open: boolean
  /** The header X, Escape or a click outside (ignored while saving). */
  onRequestClose: () => void
  title: string
  description?: string
  steps: readonly WizardStepDef<S>[]
  step: S
  onStepChange: (step: S) => void
  /** Each step's state, as the strip shows it. */
  status?: Partial<Record<S, WizardStepStatus>>
  /** The first problem in step order; null when every step is valid. */
  problem?: WizardProblem<S> | null
  /** The live summary: one line in the footer that opens the whole of it. */
  summary?: WizardSummary
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
  /** A note in the footer that replaces the first-problem link (why the action is disabled). */
  note?: ReactNode
  noteTone?: 'muted' | 'destructive'
  isLoading?: boolean
  /** Rendered after the dialog (the discard prompt). */
  after?: ReactNode
  size?: DialogSize
  'data-testid'?: string
}

export function WizardFrame<S extends string>({
  open,
  onRequestClose,
  title,
  description,
  steps,
  step,
  onStepChange,
  status,
  problem,
  summary,
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
  size = 'xl',
  'data-testid': testId,
}: WizardFrameProps<S>) {
  const { t } = useTranslation()
  const headingRef = useRef<HTMLHeadingElement>(null)
  const bodyRef = useRef<HTMLDivElement>(null)
  // What to focus after the next step change: the heading, or the first
  // field marked invalid (going to a problem).
  const [focusTarget, setFocusTarget] = useState<'heading' | 'problem' | null>(null)

  const index = steps.findIndex((s) => s.id === step)
  const isFirst = index <= 0
  const isLast = index === steps.length - 1
  const labelOf = (id: S) => steps.find((s) => s.id === id)?.label ?? ''

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

  const go = (next: S, focus: 'heading' | 'problem' = 'heading') => {
    if (next !== step) onStepChange(next)
    setFocusTarget(focus)
  }
  const goToProblem = () => go(problem?.step ?? steps[steps.length - 1].id, 'problem')

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
          className="rounded-sm font-medium text-signal-text underline-offset-2 hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-hidden"
          onClick={goToProblem}
          data-testid="wizard-fix-link"
        >
          {t('common.wizard.goTo', undefined, { name: labelOf(problem.step) })}
        </button>
      </span>
    ) : undefined
  const footerNote = note ?? problemNote

  return (
    <Dialog open={open} onOpenChange={(next) => !next && !isLoading && onRequestClose()}>
      <DialogContent
        size={size}
        className={WIZARD_SURFACE_CLASS}
        onKeyDown={onKeyDown}
        data-testid={testId}
      >
        <DialogHeader>
          <DialogTitle className="text-dialog">{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        <WizardSteps
          className="px-4 sm:px-6"
          steps={steps}
          current={step}
          onStepChange={(s) => go(s)}
          status={status}
        />

        <DialogBody ref={bodyRef} className="border-y-0 px-0 py-0 sm:px-0">
          <h3 ref={headingRef} tabIndex={-1} className="sr-only" data-testid="wizard-step-heading">
            {t('common.wizard.stepOfTotal', undefined, {
              n: index + 1,
              total: steps.length,
              name: labelOf(step),
            })}
          </h3>
          {banner}
          {children}
        </DialogBody>

        <WizardFooter
          summary={summary}
          onBack={isFirst ? undefined : () => go(steps[index - 1].id)}
          disabled={isLoading}
          noteId="wizard-note"
          noteTone={note ? noteTone : 'muted'}
          note={footerNote}
        >
          {!isLast && (
            <Button
              type="button"
              variant={submitOnEveryStep ? 'outline' : 'default'}
              onClick={() => go(steps[index + 1].id)}
              disabled={isLoading}
              data-testid="wizard-next"
            >
              {t('common.wizard.next')}
              <ArrowRight aria-hidden />
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
 * The navigation state a wizard keeps: the current step, the steps the
 * person has left, and whether a create or save was attempted.
 */
export function useWizardSteps<S extends string>(first: S) {
  const [step, setStep] = useState<S>(first)
  const stepRef = useRef(first)
  const [seen, setSeen] = useState<ReadonlySet<S>>(() => new Set())
  const [attempted, setAttempted] = useState(false)
  const changeStep = useCallback((next: S) => {
    const left = stepRef.current
    setSeen((prev) => (prev.has(left) ? prev : new Set(prev).add(left)))
    stepRef.current = next
    setStep(next)
  }, [])
  const reset = useCallback(
    (to: S = first) => {
      stepRef.current = to
      setStep(to)
      setSeen(new Set())
      setAttempted(false)
    },
    [first]
  )
  return { step, setStep: changeStep, seen, attempted, setAttempted, reset }
}
