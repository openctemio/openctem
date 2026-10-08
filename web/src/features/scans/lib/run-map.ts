/**
 * The live run map (GET /scan-runs/{id}/map) as the shared WorkflowStages
 * component draws it: the run's workflow version as steps, each step's
 * state as a status tone, a short badge (chunks, outputs, why it waits or
 * failed) and edge labels with what flowed from one step to the next.
 */
import type { ScanWorkflowStep } from '@/lib/api'
import type { RunMap, RunMapNode } from '@/lib/api/generated'
import type { StepStatusTone } from '@/features/scan-workflows/components/workflow-stages'

/** A map node state (RunMapNode.state). */
export type RunMapState =
  'pending' | 'waiting' | 'running' | 'succeeded' | 'partial' | 'failed' | 'skipped' | 'canceled'

/** The five status tones of WorkflowStages, from a map state. */
export function mapStateTone(state: string): StepStatusTone {
  switch (state as RunMapState) {
    case 'running':
      return 'running'
    case 'succeeded':
      return 'completed'
    case 'failed':
    case 'partial':
      return 'failed'
    case 'skipped':
    case 'canceled':
      return 'skipped'
    default:
      return 'pending' // pending, waiting
  }
}

/** The map's nodes as workflow steps (the fields WorkflowStages reads). */
export function mapSteps(map: RunMap | undefined): ScanWorkflowStep[] {
  return (map?.nodes ?? []).map((n, i) => ({
    id: n.step_key ?? '',
    step_key: n.step_key ?? '',
    name: n.name || n.step_key || '',
    order: i + 1,
    ui_position: { x: 0, y: 0 },
    tool: n.tool || undefined,
    capabilities: n.capabilities ?? [],
    depends_on: n.depends_on ?? [],
    timeout_seconds: n.timeout_seconds || undefined,
    max_retries: 0,
    retry_delay_seconds: 0,
  }))
}

/** Status tone per step key. */
export function mapStatus(map: RunMap | undefined): Record<string, StepStatusTone> {
  const out: Record<string, StepStatusTone> = {}
  for (const n of map?.nodes ?? []) out[n.step_key ?? ''] = mapStateTone(n.state ?? 'pending')
  return out
}

/** "1.2k" for counts over 999. */
export function compactCount(n: number): string {
  if (n < 1000) return String(n)
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0).replace(/\.0$/, '')}k`
  return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`
}

const STATE_LABEL: Record<RunMapState, string> = {
  pending: 'Not started',
  waiting: 'Waiting for a sensor',
  running: 'Running',
  succeeded: 'Done',
  partial: 'Partly done',
  failed: 'Failed',
  skipped: 'Skipped',
  canceled: 'Canceled',
}

/** A map state as a person reads it. */
export function mapStateLabel(state: string): string {
  return STATE_LABEL[state as RunMapState] ?? state
}

/**
 * The badge lines of a node: its state (with why it waits or failed), its
 * chunks while it has any, and what it produced and found.
 */
export function nodeBadgeLines(n: RunMapNode): string[] {
  const lines: string[] = []
  let state = mapStateLabel(n.state ?? 'pending')
  if ((n.state === 'failed' || n.state === 'partial' || n.state === 'skipped') && n.reason) {
    state += ` (${n.reason.toLowerCase().replace(/_/g, ' ')})`
  }
  lines.push(state)
  const total = n.chunks?.total ?? 0
  const failed = n.chunks?.failed ?? 0
  const done = (n.chunks?.completed ?? 0) + failed
  if (total > 0) {
    lines.push(`${done}/${total} chunks` + (failed ? `, ${failed} failed` : ''))
  }
  const produced = n.outputs?.total ?? 0
  const parts: string[] = []
  if (produced > 0) parts.push(`${compactCount(produced)} outputs`)
  const findings = n.findings ?? 0
  if (findings > 0) parts.push(`${compactCount(findings)} findings`)
  if (parts.length) lines.push(parts.join(', '))
  return lines
}

/** Edge label: what the upstream step produced, when it produced anything. */
export function mapEdgeLabel(
  map: RunMap | undefined
): (from: string, to: string) => string | undefined {
  const counts = new Map<string, number>()
  for (const e of map?.edges ?? []) counts.set(`${e.from}->${e.to}`, e.count ?? 0)
  return (from, to) => {
    const n = counts.get(`${from}->${to}`) ?? 0
    return n > 0 ? compactCount(n) : undefined
  }
}
