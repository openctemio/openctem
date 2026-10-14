/**
 * The live run map (GET /scan-runs/{id}/map): state labels, a step's badge
 * lines (chunks, outputs, why it waits or failed), the comparison with the
 * previous run and the warnings over the map (a step that produced nothing,
 * or whose targets the sensor's network confinement refused).
 */
import { enTranslate, type Translate } from './translate'
import type { RunMap, RunMapNode } from '@/lib/api/generated'

/** A map node state (RunMapNode.state). */
export type RunMapState =
  'pending' | 'waiting' | 'running' | 'succeeded' | 'partial' | 'failed' | 'skipped' | 'canceled'

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

/**
 * A run task's counts of targets its sensor refused: those its network
 * confinement refused every connection to (egress_refused_targets), and
 * those its target guard refused to run (guard_refused_targets: a blocked
 * or unresolvable address, an unsafe target). Both absent from older APIs.
 */
export type EgressCountedTask = {
  step_key?: string
  egress_refused_targets?: number
  guard_refused_targets?: number
}

/** The sum of one count over a step's tasks (bad values count none). */
function stepCount(
  tasks: EgressCountedTask[] | undefined,
  stepKey: string,
  field: 'egress_refused_targets' | 'guard_refused_targets'
): number {
  let n = 0
  for (const task of tasks ?? []) {
    if (task.step_key !== stepKey) continue
    const c = task[field]
    if (typeof c === 'number' && Number.isFinite(c) && c > 0) n += Math.floor(c)
  }
  return n
}

/** How many of a step's targets the sensor's egress refused, over its tasks. */
export function stepEgressRefused(tasks: EgressCountedTask[] | undefined, stepKey: string): number {
  return stepCount(tasks, stepKey, 'egress_refused_targets')
}

/** How many of a step's targets the sensor's target guard refused. */
export function stepGuardRefused(tasks: EgressCountedTask[] | undefined, stepKey: string): number {
  return stepCount(tasks, stepKey, 'guard_refused_targets')
}

const FINISHED = new Set(['succeeded', 'partial', 'failed'])

/** "Port scan could not reach 21 targets (blocked by ...)", or null. */
export function egressRefusedText(
  n: RunMapNode,
  count: number,
  t: Translate = enTranslate
): string | null {
  if (count <= 0 || !FINISHED.has(n.state ?? '')) return null
  const name = n.name || n.step_key || ''
  return count === 1
    ? t('scans.map.egressRefusedOne', undefined, { name })
    : t('scans.map.egressRefused', undefined, { name, count: compactCount(count) })
}

/** "HTTP probe: 3 targets refused by the sensor's target guard.", or null. */
export function guardRefusedText(
  n: RunMapNode,
  count: number,
  t: Translate = enTranslate
): string | null {
  if (count <= 0 || !FINISHED.has(n.state ?? '')) return null
  const name = n.name || n.step_key || ''
  return count === 1
    ? t('scans.map.guardRefusedOne', undefined, { name })
    : t('scans.map.guardRefused', undefined, { name, count: compactCount(count) })
}

/**
 * The warnings over the map: a finished step whose targets the sensor's
 * target guard refused says how many; one whose targets the sensor's
 * network confinement refused says so (it did not "produce nothing": it
 * could not reach them); otherwise a finished step that produced nothing.
 */
export function zeroOutputWarnings(
  map: RunMap | undefined,
  t: Translate = enTranslate,
  tasks?: EgressCountedTask[]
): { key: string; text: string }[] {
  const out: { key: string; text: string }[] = []
  for (const n of map?.nodes ?? []) {
    const key = n.step_key ?? ''
    // Targets the sensor's target guard refused were never run: said
    // whatever else the step did.
    const guarded = guardRefusedText(n, stepGuardRefused(tasks, key), t)
    if (guarded) out.push({ key: `${key}:guard`, text: guarded })
    const blocked = egressRefusedText(n, stepEgressRefused(tasks, key), t)
    if (blocked) {
      out.push({ key, text: blocked })
      continue
    }
    if (!producedNothing(n)) continue
    const name = n.name || n.step_key || ''
    const before = n.outputs?.previous ?? 0
    out.push({
      key,
      text:
        before > 0
          ? t('scans.map.producedNothingBefore', undefined, {
              name,
              before: compactCount(before),
            })
          : t('scans.map.producedNothing', undefined, { name }),
    })
  }
  return out
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
