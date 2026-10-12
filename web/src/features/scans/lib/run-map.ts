/**
 * The live run map (GET /scan-runs/{id}/map) as the shared WorkflowStages
 * component draws it: the run's workflow version as steps, each step's
 * state as a status tone, a short badge (chunks, outputs, why it waits or
 * failed) and edge labels with what flowed from one step to the next.
 */
import type { ScanWorkflowStep } from '@/lib/api'
import { enTranslate, type Translate } from './translate'
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

const MAP_STATES = new Set<string>([
  'pending',
  'waiting',
  'running',
  'succeeded',
  'partial',
  'failed',
  'skipped',
  'canceled',
])

/** A map state as a person reads it. */
export function mapStateLabel(state: string, t: Translate = enTranslate): string {
  return MAP_STATES.has(state) ? t(`scans.map.state.${state}`) : state
}

/**
 * The badge lines of a node: its state (with why it waits or failed), its
 * chunks while it has any, and what it produced and found.
 */
export function nodeBadgeLines(n: RunMapNode, t: Translate = enTranslate): string[] {
  const lines: string[] = []
  let state = mapStateLabel(n.state ?? 'pending', t)
  if ((n.state === 'failed' || n.state === 'partial' || n.state === 'skipped') && n.reason) {
    state += ` (${n.reason.toLowerCase().replace(/_/g, ' ')})`
  }
  lines.push(state)
  const total = n.chunks?.total ?? 0
  const failed = n.chunks?.failed ?? 0
  const done = (n.chunks?.completed ?? 0) + failed
  if (total > 0) {
    lines.push(
      t('scans.map.chunks', undefined, { done, total }) +
        (failed ? t('scans.map.chunksFailed', undefined, { count: failed }) : '')
    )
  }
  const produced = n.outputs?.total ?? 0
  const parts: string[] = []
  if (produced > 0) parts.push(t('scans.map.outputs', undefined, { count: compactCount(produced) }))
  const findings = n.findings ?? 0
  if (findings > 0)
    parts.push(t('scans.map.findings', undefined, { count: compactCount(findings) }))
  if (parts.length) lines.push(parts.join(', '))
  const delta = outputsDeltaLabel(n, t)
  if (delta) lines.push(delta)
  if (producedNothing(n)) lines.push(t('scans.map.noOutput'))
  return lines
}

/**
 * How a step's outputs compare with the previous run of the scan:
 * "+3 new, 1 gone", "same as last run", or null without a previous run (or
 * when neither run produced anything).
 */
export function outputsDeltaLabel(n: RunMapNode, t: Translate = enTranslate): string | null {
  const o = n.outputs
  if (o?.previous === undefined) return null
  const added = o.added ?? 0
  const gone = o.gone ?? 0
  if (added === 0 && gone === 0) {
    return (o.total ?? 0) > 0 ? t('scans.map.sameAsLast') : null
  }
  const parts: string[] = []
  if (added > 0) parts.push(t('scans.map.newCount', undefined, { count: compactCount(added) }))
  if (gone > 0) parts.push(t('scans.map.goneCount', undefined, { count: compactCount(gone) }))
  return parts.join(', ')
}

/**
 * A step that finished and produced nothing: no asset in the caller's scope
 * and no finding. Worth a look: a tool that silently returns nothing looks
 * like a clean result.
 */
export function producedNothing(n: RunMapNode): boolean {
  if (n.state !== 'succeeded' && n.state !== 'partial') return false
  return (n.outputs?.total ?? 0) === 0 && (n.findings ?? 0) === 0
}

/** The finished steps that produced nothing, and the warning to show for each. */
export function zeroOutputWarnings(
  map: RunMap | undefined,
  t: Translate = enTranslate
): { key: string; text: string }[] {
  return (map?.nodes ?? []).filter(producedNothing).map((n) => {
    const name = n.name || n.step_key || ''
    const before = n.outputs?.previous ?? 0
    return {
      key: n.step_key ?? '',
      text:
        before > 0
          ? t('scans.map.producedNothingBefore', undefined, {
              name,
              before: compactCount(before),
            })
          : t('scans.map.producedNothing', undefined, { name }),
    }
  })
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

/** The tasks of one step of the run (by step key). */
export function stepTasks<T extends { step_key?: string }>(
  tasks: T[] | undefined,
  stepKey: string
): T[] {
  return (tasks ?? []).filter((t) => t.step_key === stepKey)
}

/** A step's outputs by asset type, most first: [type, count]. */
export function outputsByType(n: RunMapNode | undefined): [string, number][] {
  return Object.entries(n?.outputs?.by_type ?? {})
    .map(([t, c]): [string, number] => [t, c ?? 0])
    .filter(([, c]) => c > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
}
