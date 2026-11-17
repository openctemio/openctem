'use client'

/**
 * The scan wizard, one for New scan and Edit scan: the shared wizard frame
 * (`features/shared/components/forms/wizard.tsx`) with the scan's steps,
 * their problems and the live summary. Every step can be opened at any time
 * and shows whether it is complete; the primary action stays disabled until
 * every step is valid, with the first problem named in the footer as a link
 * to its step. The summary is one line in the footer that opens the whole of
 * it. Design: research/418.
 */

import { type ReactNode } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import {
  WizardFrame,
  useWizardSteps as useSharedWizardSteps,
} from '@/features/shared/components/forms'
import { stepLabelKey, type ScanWizardStep } from './scan-stepper'
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
  /** The whole summary, opened from its line in the footer. */
  summary: ReactNode
  /** The summary in one line. */
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
  /** A note in the footer that replaces the first-problem link (why the action is disabled). */
  note?: ReactNode
  noteTone?: 'muted' | 'destructive'
  isLoading?: boolean
  /** Rendered after the dialog (the discard prompt). */
  after?: ReactNode
}

export function ScanWizard({
  steps,
  issues,
  attempted,
  seen,
  summary,
  summaryLine,
  ...frame
}: ScanWizardProps) {
  const { t } = useTranslation()
  return (
    <WizardFrame
      {...frame}
      data-testid="scan-wizard"
      steps={steps.map((id) => ({ id, label: t(stepLabelKey(id)) }))}
      status={stepStatuses(issues, steps, seen, attempted)}
      problem={firstIssue(issues, steps)}
      summary={{ title: t('scans.summaryPanel.title'), line: summaryLine, content: summary }}
    />
  )
}

/**
 * The navigation state a wizard dialog keeps: the current step, the steps
 * the person has left, and whether a create or save was attempted.
 */
export function useWizardSteps(first: ScanWizardStep) {
  return useSharedWizardSteps<ScanWizardStep>(first)
}
