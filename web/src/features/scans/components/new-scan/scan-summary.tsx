'use client'

/**
 * The live summary of the scan wizard, on every step: what will run, at what
 * intensity (in plain words, and whether this scan needs an approval), against
 * how many targets, when (with the next runs from the API), about how many
 * jobs, and what still has to be fixed before it can be created, each problem
 * a link to its step. Desktop: a sticky column beside the step. Phone and
 * tablet: a one-line bar above the footer that opens it. Every figure comes
 * from the form or the server's answers; nothing is decided here.
 * Design: research/418.
 */

import { useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronUp,
  CircleSlash,
  Clock,
  ShieldCheck,
} from 'lucide-react'
import {
  stepFix,
  stepReason,
  type StepReadiness,
  type WorkflowReadiness,
} from '@/features/scan-workflows/lib/readiness'
import { useTranslation } from '@/context/i18n-provider'
import { DetailField, DetailFieldGrid } from '@/features/shared/components/detail-sheet'
import { cn } from '@/lib/utils'
import type { ScanApprovalEvaluation } from '@/lib/api/scan-approval-hooks'
import type { NewScanFormData } from '../../types'
import { SchedulePreview } from '../schedule-preview'
import { scheduleSummary } from './review-step'
import { stepLabelKey, type ScanWizardStep } from './scan-stepper'
import { estimateJobs, stepsThatRun, type StepIssues } from '../../lib/wizard-validity'
import { schedulePreviewRequestFromForm } from '../../lib/schedule-preview'
import { scheduleError } from '../../lib/scan-form'
import type { Translate } from '../../lib/translate'

export interface ScanSummaryFacts {
  data: NewScanFormData
  /** The scanner or workflow, by name. */
  whatLabel: string
  /** Direct targets (typed, picked and expanded), de-duplicated. */
  directCount: number
  /** Scope check answers: ready and blocked direct targets (unknown while checking). */
  ready?: number
  blocked?: number
  checking?: boolean
  approval?: ScanApprovalEvaluation | null
  /** The chosen workflow's readiness, per step (a workflow scan). */
  workflowReadiness?: WorkflowReadiness
  issues: StepIssues
  steps: readonly ScanWizardStep[]
  /** Show every problem (after a create attempt) or only those of visited steps. */
  shownSteps: ReadonlySet<ScanWizardStep>
  onGo: (step: ScanWizardStep) => void
}

export function ScanSummaryContent({
  data,
  whatLabel,
  directCount,
  ready,
  blocked,
  checking,
  approval,
  workflowReadiness,
  issues,
  steps,
  shownSteps,
  onGo,
}: ScanSummaryFacts) {
  const { t } = useTranslation()
  const groups = data.targets.assetGroupIds.length
  const jobs = estimateJobs(directCount, data.maxConcurrent)
  const scheduleRequest =
    !data.schedule.runImmediately &&
    !data.schedule.saveOnly &&
    !scheduleError(data, { requireFuture: false }, t)
      ? schedulePreviewRequestFromForm(data)
      : null
  const problems = steps.flatMap((step) =>
    shownSteps.has(step) ? (issues[step] ?? []).map((message) => ({ step, message })) : []
  )
  const roles = approval?.approver_roles ?? []

  return (
    <div className="min-w-0 space-y-4" data-testid="scan-summary">
      <DetailFieldGrid className="sm:grid-cols-1">
        <DetailField full label={t('scans.summaryPanel.what')}>
          {data.name.trim() ? <span className="block font-medium">{data.name.trim()}</span> : null}
          <span className={cn(!data.name.trim() && 'text-muted-foreground')}>{whatLabel}</span>
        </DetailField>
        {data.mode === 'workflow' && workflowReadiness && workflowReadiness.steps.length > 0 && (
          <DetailField full label={t('scans.summaryPanel.steps')}>
            {(() => {
              const n = stepsThatRun(workflowReadiness)
              return n ? (
                <span className="mb-1.5 block" data-testid="summary-steps-count">
                  {t('scans.summaryPanel.stepsRun', undefined, { run: n.run, total: n.total })}
                </span>
              ) : null
            })()}
            <ul className="space-y-1.5" data-testid="summary-steps">
              {workflowReadiness.steps.map((step) => (
                <StepLine key={step.step_key} step={step} />
              ))}
            </ul>
          </DetailField>
        )}
        <DetailField full label={t('scans.summaryPanel.intensity')}>
          <span className="block font-medium">{t(`scans.intensity.${data.intensity}`)}</span>
          <span className="block text-xs text-muted-foreground">
            {t(`scans.summaryPanel.intensityMeaning.${data.intensity}`)}
          </span>
          {approval?.required && (
            <span className="mt-1 flex items-start gap-1.5 text-xs" data-testid="summary-approval">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
              <span>
                {roles.length > 0
                  ? t('scans.summaryPanel.approvalBy', undefined, {
                      count: approval.approvals ?? 1,
                      roles: roles.join(', '),
                    })
                  : t('scans.summaryPanel.approval', undefined, { count: approval.approvals ?? 1 })}
              </span>
            </span>
          )}
        </DetailField>
        <DetailField full label={t('scans.summaryPanel.targets')}>
          <span className="block" data-testid="summary-targets">
            {directCount === 0 && groups === 0
              ? t('scans.summaryPanel.noTargets')
              : groups > 0
                ? t('scans.summaryPanel.targetsAndGroups', undefined, {
                    count: directCount,
                    groups,
                  })
                : t('scans.summaryPanel.targetsCount', undefined, { count: directCount })}
          </span>
          {directCount > 0 && (
            <span className="block text-xs text-muted-foreground">
              {checking
                ? t('scans.targetList.checking')
                : ready !== undefined && blocked !== undefined
                  ? t('scans.summaryPanel.readiness', undefined, { ready, blocked })
                  : null}
            </span>
          )}
        </DetailField>
        <DetailField full label={t('scans.summaryPanel.schedule')}>
          <span className="block">{scheduleSummary(data, t)}</span>
          {scheduleRequest && (
            <div className="mt-2">
              <SchedulePreview request={scheduleRequest} />
            </div>
          )}
        </DetailField>
        <DetailField full label={t('scans.summaryPanel.jobs')}>
          {directCount === 0 && groups === 0
            ? t('scans.summaryPanel.jobsNone')
            : groups > 0
              ? t('scans.summaryPanel.jobsWithGroups', undefined, {
                  count: jobs,
                  per: data.maxConcurrent || 10,
                })
              : t('scans.summaryPanel.jobsCount', undefined, {
                  count: jobs,
                  per: data.maxConcurrent || 10,
                })}
        </DetailField>
      </DetailFieldGrid>
      {problems.length > 0 && (
        <section aria-label={t('scans.summaryPanel.beforeCreate')} className="space-y-1.5">
          <h4 className="text-xs font-medium text-muted-foreground">
            {t('scans.summaryPanel.beforeCreate')}
          </h4>
          <ul className="space-y-1">
            {problems.map((p, i) => (
              <li key={`${p.step}:${i}`}>
                <button
                  type="button"
                  onClick={() => onGo(p.step)}
                  className="flex min-h-9 w-full items-start gap-1.5 rounded-md px-1 py-1 text-start text-sm hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-hidden"
                  data-testid="summary-problem"
                >
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
                  <span className="min-w-0">
                    <span className="block text-xs text-muted-foreground">
                      {t(stepLabelKey(p.step))}
                    </span>
                    <span className="block">{p.message}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  )
}

/** One workflow step: the tool it runs with, or why it waits, is skipped or cannot run. */
function StepLine({ step }: { step: StepReadiness }) {
  const { t } = useTranslation()
  const reason = stepReason(step, t)
  // What adding a tool or a sensor would cover; the scan is saved and runs
  // the other steps meanwhile.
  const fix = step.state === 'blocked' || step.state === 'ci_only' ? stepFix(step, t) : undefined
  const text =
    step.state === 'ready'
      ? step.tool
        ? t('scans.summaryPanel.stepRunsWith', undefined, { tool: step.tool })
        : t('scans.summaryPanel.stepReady')
      : step.state === 'skipped'
        ? t('scans.summaryPanel.stepSkipped', undefined, {
            capability: step.capability ?? step.name,
          })
        : step.state === 'blocked'
          ? t('scans.summaryPanel.stepWillSkip', undefined, { reason: reason ?? '' })
          : (reason ?? '')
  const Icon =
    step.state === 'ready'
      ? CheckCircle2
      : step.state === 'skipped'
        ? CircleSlash
        : step.state === 'waiting'
          ? Clock
          : AlertTriangle
  return (
    <li className="flex items-start gap-1.5" data-state={step.state}>
      <Icon
        className={cn(
          'mt-0.5 h-3.5 w-3.5 shrink-0',
          step.state === 'ready' && 'text-signal-text',
          (step.state === 'skipped' || step.state === 'waiting') && 'text-muted-foreground',
          (step.state === 'blocked' || step.state === 'ci_only') && 'text-warning'
        )}
        aria-hidden
      />
      <span className="min-w-0 text-xs">
        <span className="block font-medium">{step.name}</span>
        <span className="block text-muted-foreground">{text}</span>
        {fix && <span className="block">{fix}</span>}
      </span>
    </li>
  )
}

/** The one-line summary of the phone bar. */
export function summaryLine(
  facts: Pick<ScanSummaryFacts, 'data' | 'directCount'>,
  t: Translate
): string {
  const groups = facts.data.targets.assetGroupIds.length
  const targets =
    groups > 0
      ? t('scans.summaryPanel.targetsAndGroups', undefined, { count: facts.directCount, groups })
      : t('scans.summaryPanel.targetsCount', undefined, { count: facts.directCount })
  return [
    targets,
    scheduleSummary(facts.data, t),
    t(`scans.intensity.${facts.data.intensity}`),
  ].join(', ')
}

/** Phone and tablet: a bar above the footer that opens the summary. */
export function ScanSummaryBar({ line, children }: { line: string; children: React.ReactNode }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  return (
    <div className="w-full min-w-0 border-b pb-1 lg:hidden" data-testid="summary-bar">
      <button
        type="button"
        className="flex min-h-11 w-full min-w-0 items-center gap-2 text-start text-sm"
        aria-expanded={open}
        aria-controls="scan-summary-sheet"
        onClick={() => setOpen((o) => !o)}
      >
        <span className="shrink-0 font-medium">{t('scans.summaryPanel.title')}</span>
        <span className="min-w-0 flex-1 truncate text-muted-foreground">{line}</span>
        <ChevronUp
          className={cn('h-4 w-4 shrink-0 transition-transform', !open && 'rotate-180')}
          aria-hidden
        />
      </button>
      {open && (
        <div
          id="scan-summary-sheet"
          className="max-h-[45dvh] overflow-y-auto overscroll-contain pb-3"
        >
          {children}
        </div>
      )}
    </div>
  )
}
