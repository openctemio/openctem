'use client'

import { useCallback, useMemo, useState } from 'react'
import Link from 'next/link'
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  BackgroundVariant,
  MarkerType,
  type Edge,
  type Node,
} from '@xyflow/react'
import { AlertTriangle, GitBranch, ListTree, Workflow } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { layeredLayout } from '@/components/flow/layered-layout'
import { useTranslation } from '@/context/i18n-provider'
import type { ScanWorkflowStep } from '@/lib/api'
import { cn } from '@/lib/utils'
import { safeHref } from '@/lib/safe-href'
import { capabilityForStep, stepEdges, type CapabilityTable } from '../lib/capability-graph'
import { selectionOf } from '../lib/step-settings'
import { formatDuration, planStages } from '../lib/workflow-stages'
import { useCapabilityTable } from '../lib/use-capability-table'
import { useToolsWithConfig } from '@/lib/api/tool-hooks'

export type StepStatusTone = 'pending' | 'running' | 'completed' | 'failed' | 'skipped'

const TONE: Record<StepStatusTone, string> = {
  pending: 'border-muted',
  running: 'border-info bg-info/5',
  completed: 'border-success bg-success/5',
  failed: 'border-destructive bg-destructive/5',
  skipped: 'border-muted opacity-70',
}

export interface WorkflowStagesProps {
  steps: ScanWorkflowStep[]
  /** The capability catalog (names, tools); steps show their raw words without it. */
  table?: CapabilityTable
  /** The workflow's max parallel steps setting. */
  maxParallel?: number
  /** Tool name -> an online sensor can run it now (unknown when absent). */
  toolAvailable?: (tool: string) => boolean | undefined
  /** The editable draft differs from what runs (shown as a warning). */
  draftChanged?: boolean
  /** Status per step key (the run page). */
  status?: Record<string, StepStatusTone>
  /** Link to the builder ("Open in builder"). */
  builderHref?: string
  className?: string
}

/**
 * A workflow's steps as stages computed from its dependency graph: steps
 * of one stage run in parallel, and a step that waits for several shows
 * them. Each step reads capability first, then how it picks its tool. A
 * read-only graph is one toggle away. Shared by the workflow detail sheet,
 * the New-scan preview, the template library and the run page.
 */
export function WorkflowStages({
  steps,
  table,
  maxParallel,
  toolAvailable,
  draftChanged,
  status,
  builderHref,
  className,
}: WorkflowStagesProps) {
  const { t } = useTranslation()
  const [view, setView] = useState<'stages' | 'graph'>('stages')
  const plan = useMemo(() => planStages(steps), [steps])
  const byKey = useMemo(() => new Map(steps.map((s) => [s.step_key, s])), [steps])
  const nameOf = (key: string) => byKey.get(key)?.name || key

  const warnings: string[] = []
  if (draftChanged) {
    warnings.push(
      t(
        'workflowStages.draftChanged',
        'The draft has changes that are not published: runs use the published version.'
      )
    )
  }
  if (maxParallel && plan.maxConcurrent > maxParallel) {
    warnings.push(
      t(
        'workflowStages.parallelLimit',
        'Up to {n} steps could run at once, but the workflow allows {limit}: some wait.',
        { n: plan.maxConcurrent, limit: maxParallel }
      )
    )
  }

  if (steps.length === 0) {
    return (
      <p className={cn('text-sm text-muted-foreground', className)}>
        {t('workflowStages.empty', 'No steps configured.')}
      </p>
    )
  }

  return (
    <div className={cn('space-y-3', className)}>
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span>
          {t('workflowStages.summaryConcurrent', 'At most {n} at once', {
            n: plan.maxConcurrent,
          })}
          {maxParallel
            ? ` ${t('workflowStages.summaryLimit', '(limit {limit})', { limit: maxParallel })}`
            : ''}
        </span>
        <span aria-hidden>·</span>
        <span>
          {t('workflowStages.summaryPath', 'Longest chain: {n} steps', {
            n: plan.criticalPath.length,
          })}
        </span>
        <span aria-hidden>·</span>
        <span>
          {t('workflowStages.summaryDuration', 'Up to {d} by step timeouts', {
            d: formatDuration(plan.estimatedSeconds),
          })}
        </span>
        <div className="ms-auto flex items-center gap-1">
          <div role="group" aria-label={t('workflowStages.view', 'View')} className="flex">
            <Button
              type="button"
              size="sm"
              variant={view === 'stages' ? 'secondary' : 'ghost'}
              className="h-7 px-2 text-xs"
              aria-pressed={view === 'stages'}
              onClick={() => setView('stages')}
            >
              <ListTree className="me-1 h-3.5 w-3.5" />
              {t('workflowStages.viewStages', 'Stages')}
            </Button>
            <Button
              type="button"
              size="sm"
              variant={view === 'graph' ? 'secondary' : 'ghost'}
              className="h-7 px-2 text-xs"
              aria-pressed={view === 'graph'}
              onClick={() => setView('graph')}
            >
              <GitBranch className="me-1 h-3.5 w-3.5" />
              {t('workflowStages.viewGraph', 'Graph')}
            </Button>
          </div>
          {builderHref && (
            <Button asChild size="sm" variant="outline" className="h-7 px-2 text-xs">
              <Link href={safeHref(builderHref) ?? '#'}>
                <Workflow className="me-1 h-3.5 w-3.5" />
                {t('workflowStages.openBuilder', 'Open in builder')}
              </Link>
            </Button>
          )}
        </div>
      </div>

      {plan.problems.map((p) => (
        <p
          key={p.kind}
          role="alert"
          className="flex items-start gap-1.5 rounded-md border border-destructive/40 px-2 py-1.5 text-xs text-destructive"
        >
          <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0" />
          {p.kind === 'cycle'
            ? t('workflowStages.cycle', 'These steps wait for each other in a loop: {steps}.', {
                steps: p.steps.map(nameOf).join(', '),
              })
            : t('workflowStages.missing', '{steps} wait for steps that do not exist: {missing}.', {
                steps: p.steps.map(nameOf).join(', '),
                missing: (p.missing ?? []).join(', '),
              })}
        </p>
      ))}
      {warnings.map((w) => (
        <p
          key={w}
          role="status"
          className="flex items-start gap-1.5 rounded-md border border-warning/40 px-2 py-1.5 text-xs text-warning"
        >
          <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0" />
          {w}
        </p>
      ))}

      {view === 'graph' ? (
        <MiniGraph steps={steps} status={status} />
      ) : (
        <ol className="space-y-3">
          {plan.stages.map((stage, idx) => (
            <li key={idx} aria-labelledby={`wf-stage-${idx}`}>
              <h4
                id={`wf-stage-${idx}`}
                className="mb-1.5 flex items-center gap-2 text-xs font-semibold text-muted-foreground"
              >
                {t('workflowStages.stage', 'Stage {n}', { n: idx + 1 })}
                {stage.length > 1 && (
                  <Badge variant="outline" className="px-1.5 py-0 text-[10px] font-normal">
                    {t('workflowStages.parallel', '{n} in parallel', { n: stage.length })}
                  </Badge>
                )}
              </h4>
              <ul className="grid gap-2 sm:grid-cols-2">
                {stage.map((step) => (
                  <StepCard
                    key={step.id || step.step_key}
                    step={step}
                    table={table}
                    waitsFor={(plan.waitsFor[step.step_key] ?? []).map(nameOf)}
                    toolAvailable={toolAvailable}
                    tone={status?.[step.step_key]}
                  />
                ))}
              </ul>
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}

function StepCard({
  step,
  table,
  waitsFor,
  toolAvailable,
  tone,
}: {
  step: ScanWorkflowStep
  table?: CapabilityTable
  waitsFor: string[]
  toolAvailable?: (tool: string) => boolean | undefined
  tone?: StepStatusTone
}) {
  const { t } = useTranslation()
  const cap = table ? capabilityForStep(table, step) : null
  const mode = selectionOf(step)
  const toolText =
    mode === 'pin'
      ? t('workflowStages.toolPinned', 'Pinned: {tool}', { tool: step.tool ?? '' })
      : mode === 'prefer'
        ? t('workflowStages.toolPreferred', 'Preferred: {tools}', {
            tools: (step.prefer_tools ?? []).join(', '),
          })
        : t('workflowStages.toolAny', 'Any tool')
  // Tools that could run the step; unavailable when none of them can.
  const candidates =
    mode === 'pin'
      ? [step.tool ?? '']
      : mode === 'prefer'
        ? (step.prefer_tools ?? [])
        : (cap?.tools ?? [])
  const answers = toolAvailable ? candidates.map((c) => toolAvailable(c)) : []
  const unavailable = answers.length > 0 && answers.every((a) => a === false)

  return (
    <li className={cn('rounded-md border px-3 py-2', tone ? TONE[tone] : undefined)}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-medium break-words">{cap?.name ?? step.name}</p>
          {cap && step.name && step.name !== cap.name && (
            <p className="text-xs text-muted-foreground break-words">{step.name}</p>
          )}
          {!cap && (step.capabilities ?? []).length > 0 && (
            <p className="text-xs text-muted-foreground">{(step.capabilities ?? []).join(', ')}</p>
          )}
        </div>
        {tone && (
          <Badge variant="outline" className="shrink-0 px-1.5 py-0 text-[10px]">
            {t(`workflowStages.status.${tone}`, tone)}
          </Badge>
        )}
      </div>
      <p className="mt-1 text-xs text-muted-foreground">{toolText}</p>
      {waitsFor.length > 1 && (
        <p className="mt-0.5 text-xs text-muted-foreground">
          {t('workflowStages.waitsFor', 'Waits for: {steps}', { steps: waitsFor.join(', ') })}
        </p>
      )}
      {unavailable && (
        <p className="mt-1 flex items-start gap-1 text-xs text-warning">
          <AlertTriangle className="mt-px h-3 w-3 shrink-0" />
          {t('workflowStages.unavailable', 'No online sensor offers {tools}.', {
            tools: candidates.join(', '),
          })}
        </p>
      )}
    </li>
  )
}

function MiniGraph({
  steps,
  status,
}: {
  steps: ScanWorkflowStep[]
  status?: Record<string, StepStatusTone>
}) {
  const { t } = useTranslation()
  const { nodes, edges } = useMemo(() => {
    const byId = new Map(steps.map((s) => [s.id, s]))
    const flowEdges = stepEdges(steps)
    const pos = layeredLayout(
      steps.map((s) => s.id),
      flowEdges,
      { direction: 'TB', columnWidth: 200, rowHeight: 90 }
    )
    const n: Node[] = steps.map((s) => ({
      id: s.id,
      position: pos[s.id],
      data: { label: s.name || s.step_key },
      className: cn('!w-44 !text-xs', status?.[s.step_key] && TONE[status[s.step_key]]),
      draggable: false,
      connectable: false,
    }))
    const e: Edge[] = flowEdges
      .filter((x) => byId.has(x.source) && byId.has(x.target))
      .map((x) => ({
        id: `${x.source}->${x.target}`,
        source: x.source,
        target: x.target,
        markerEnd: { type: MarkerType.ArrowClosed },
      }))
    return { nodes: n, edges: e }
  }, [steps, status])

  return (
    <div
      className="h-80 w-full rounded-md border"
      role="img"
      aria-label={t('workflowStages.graphLabel', 'Graph of the workflow steps')}
    >
      <ReactFlowProvider>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={false}
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={16} size={1} />
        </ReactFlow>
      </ReactFlowProvider>
    </div>
  )
}

/**
 * WorkflowStages with the capability catalog and the tool availability of
 * the organization loaded (one shared request each).
 */
export function WorkflowStagesView(props: Omit<WorkflowStagesProps, 'table' | 'toolAvailable'>) {
  const { table } = useCapabilityTable()
  const { data: tools } = useToolsWithConfig()
  const available = useMemo(() => {
    const m = new Map<string, boolean>()
    for (const t of tools?.items ?? []) m.set(t.tool.name, !!t.is_available)
    return m
  }, [tools])
  const toolAvailable = useCallback((name: string) => available.get(name), [available])
  return <WorkflowStages {...props} table={table} toolAvailable={toolAvailable} />
}
