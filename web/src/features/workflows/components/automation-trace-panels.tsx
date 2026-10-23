'use client'

import { CircleAlert, OctagonX } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import type {
  AutomationMode,
  NodeRun,
  WorkflowDelivery,
  WorkflowValidateResponse,
  WorkflowValidationIssue,
} from '@/lib/api/workflow-types'
import { skippedEntries } from '../lib/automation-lifecycle'
import { useAutomationLabels } from '../lib/use-automation-labels'

/**
 * Validate results: blocking problems and warnings. One with a node key
 * selects that step on the canvas.
 */
export function ValidationPanel({
  result,
  nodeName,
  onSelect,
}: {
  result: WorkflowValidateResponse
  nodeName: (nodeKey: string) => string | undefined
  onSelect: (nodeKey: string) => void
}) {
  const { t } = useTranslation()
  const labels = useAutomationLabels()
  const row = (issue: WorkflowValidationIssue, i: number, blocking: boolean) => {
    const Icon = blocking ? OctagonX : CircleAlert
    const text = labels.issue(issue.code, issue.message)
    const step = issue.node_key ? (nodeName(issue.node_key) ?? issue.node_key) : null
    const body = (
      <>
        <Icon
          className={
            blocking
              ? 'mt-0.5 h-4 w-4 shrink-0 text-destructive'
              : 'mt-0.5 h-4 w-4 shrink-0 text-warning'
          }
          aria-hidden
        />
        <span className="min-w-0">
          {step && <span className="block text-xs font-medium">{step}</span>}
          <span className="block break-words">{text}</span>
        </span>
      </>
    )
    return (
      <li key={`${issue.code}-${issue.node_key ?? ''}-${i}`}>
        {issue.node_key ? (
          <button
            type="button"
            className="flex w-full gap-2 rounded-md px-2 py-1.5 text-start text-sm hover:bg-muted"
            onClick={() => onSelect(issue.node_key!)}
            data-testid={`issue-${issue.code}`}
          >
            {body}
          </button>
        ) : (
          <div className="flex gap-2 px-2 py-1.5 text-sm" data-testid={`issue-${issue.code}`}>
            {body}
          </div>
        )}
      </li>
    )
  }
  const none = result.problems.length === 0 && result.warnings.length === 0
  return (
    <section
      className="rounded-lg border p-3"
      aria-labelledby="automation-checks-title"
      data-testid="validation-panel"
    >
      <h3 id="automation-checks-title" className="mb-2 text-sm font-semibold">
        {t('automations.validate.title', 'Checks')}
      </h3>
      {none ? (
        <p className="text-sm text-muted-foreground">
          {t('automations.validate.clean', 'No problems found.')}
        </p>
      ) : (
        <>
          {result.problems.length > 0 && (
            <>
              <p className="px-2 text-xs text-muted-foreground">
                {t('automations.validate.problems', 'Problems ({n}), fix before going live', {
                  n: result.problems.length,
                })}
              </p>
              <ul>{result.problems.map((p, i) => row(p, i, true))}</ul>
            </>
          )}
          {result.warnings.length > 0 && (
            <>
              <p className="mt-2 px-2 text-xs text-muted-foreground">
                {t('automations.validate.warnings', 'Warnings ({n})', {
                  n: result.warnings.length,
                })}
              </p>
              <ul>{result.warnings.map((w, i) => row(w, i, false))}</ul>
            </>
          )}
        </>
      )}
    </section>
  )
}

type DeliveryRow = Omit<WorkflowDelivery, 'id' | 'created_at'> & { id?: string }

/**
 * What a run sent or would send. A simulate delivery never leaves the
 * platform and says so.
 */
export function DeliveriesList({
  deliveries,
  mode,
}: {
  deliveries: DeliveryRow[]
  mode: AutomationMode
}) {
  const { t } = useTranslation()
  const labels = useAutomationLabels()
  if (deliveries.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        {mode === 'simulate'
          ? t('automations.deliveries.noneSimulate', 'Nothing would be sent.')
          : t('automations.deliveries.none', 'Nothing was sent.')}
      </p>
    )
  }
  const status = (d: DeliveryRow) => {
    if (d.mode === 'simulate' || d.status === 'simulated')
      return t('automations.deliveries.neverSent', 'Never sent: simulate')
    if (d.status === 'sent') return t('automations.deliveries.sent', 'Sent')
    if (d.status === 'held') return t('automations.deliveries.held', 'Held')
    if (d.status === 'failed') return t('automations.deliveries.failed', 'Failed')
    return d.status
  }
  return (
    <ul className="divide-y rounded-lg border" data-testid="deliveries-list">
      {deliveries.map((d, i) => (
        <li key={d.id ?? `${d.node_key}-${i}`} className="space-y-0.5 px-3 py-2 text-sm">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium">{labels.channel(d.channel)}</span>
            <Badge variant="outline" className="text-xs">
              {status(d)}
            </Badge>
          </div>
          <div className="font-mono text-xs break-all text-muted-foreground">{d.target}</div>
          {d.payload?.title && <div className="break-words">{d.payload.title}</div>}
          {d.external_ref && (
            <div className="font-mono text-xs text-muted-foreground">{d.external_ref}</div>
          )}
        </li>
      ))}
    </ul>
  )
}

export interface TraceRow {
  nodeKey: string
  name: string
  status?: string
  in: number
  out: number
  skipped?: Record<string, number>
  error?: string
}

/** Rows of a run trace from its node runs, named after the workflow's steps. */
export function traceRowsFromNodeRuns(
  runs: NodeRun[] | undefined,
  nodeName: (nodeKey: string) => string | undefined
): TraceRow[] {
  return (runs ?? []).map((r) => ({
    nodeKey: r.node_key,
    name: nodeName(r.node_key) ?? r.node_key,
    status: r.status,
    in: r.in_count ?? 0,
    out: r.out_count ?? 0,
    skipped: r.skipped,
    error: r.error_message,
  }))
}

/**
 * The per-step trace: a table on wide screens, cards on a phone, so nothing
 * scrolls sideways at 390px.
 */
export function StepTrace({ rows }: { rows: TraceRow[] }) {
  const { t } = useTranslation()
  const labels = useAutomationLabels()
  const reasons = (r: TraceRow) =>
    skippedEntries(r.skipped)
      .map(([reason, n]) =>
        t('automations.counts.skipped', '{n} {reason}', { n, reason: labels.skipReason(reason) })
      )
      .join(', ')
  const statusLabel = (s?: string) =>
    s === 'completed'
      ? t('automations.trace.status.completed', 'Completed')
      : s === 'skipped'
        ? t('automations.trace.status.skipped', 'Skipped')
        : s === 'failed'
          ? t('automations.trace.status.failed', 'Failed')
          : s === 'running'
            ? t('automations.trace.status.running', 'Running')
            : s === 'pending'
              ? t('automations.trace.status.pending', 'Pending')
              : (s ?? '—')
  if (rows.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        {t('automations.trace.empty', 'No step has run yet.')}
      </p>
    )
  }
  return (
    <div data-testid="step-trace">
      <table className="hidden w-full text-sm md:table">
        <thead className="text-start text-xs text-muted-foreground">
          <tr className="border-b">
            <th className="py-2 pe-2 text-start font-medium">
              {t('automations.trace.step', 'Step')}
            </th>
            <th className="py-2 pe-2 text-start font-medium">
              {t('automations.trace.statusColumn', 'Status')}
            </th>
            <th className="py-2 pe-2 text-end font-medium">{t('automations.trace.in', 'In')}</th>
            <th className="py-2 pe-2 text-end font-medium">{t('automations.trace.out', 'Out')}</th>
            <th className="py-2 text-start font-medium">
              {t('automations.trace.skipped', 'Skipped, with reason')}
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.nodeKey} className="border-b align-top last:border-0">
              <td className="py-2 pe-2">{r.name}</td>
              <td className="py-2 pe-2">{statusLabel(r.status)}</td>
              <td className="py-2 pe-2 text-end tabular-nums">{r.in}</td>
              <td className="py-2 pe-2 text-end tabular-nums">{r.out}</td>
              <td className="py-2">
                {reasons(r) || '—'}
                {r.error && <div className="text-destructive">{r.error}</div>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <ul className="space-y-2 md:hidden">
        {rows.map((r) => (
          <li key={r.nodeKey} className="rounded-lg border p-3 text-sm">
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium break-words">{r.name}</span>
              <span className="text-xs text-muted-foreground">{statusLabel(r.status)}</span>
            </div>
            <div className="tabular-nums">
              {t('automations.trace.inOut', '{in} in · {out} out', { in: r.in, out: r.out })}
            </div>
            {reasons(r) && <div className="text-muted-foreground">{reasons(r)}</div>}
            {r.error && <div className="text-destructive">{r.error}</div>}
          </li>
        ))}
      </ul>
    </div>
  )
}
