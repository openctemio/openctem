import { readFileSync } from 'node:fs'
import { relative, sep } from 'node:path'
import { BaseSequencer } from 'vitest/node'
import type { TestSpecification } from 'vitest/node'

/**
 * Splits the test files of `--shard=i/n` by recorded run time instead of by
 * count: files go longest first to the least loaded shard, so the shards finish
 * together. CI records the file durations of full runs (merge queue, push) and
 * hands the newest to every shard through VITEST_DURATIONS, a JSON object
 * {"<path relative to web/>": milliseconds}.
 *
 * Without that file, or when it is unreadable, the split is Vitest's own. Every
 * file is on exactly one shard either way, so a stale or wrong durations file
 * can only unbalance the shards, never drop a test. The plan depends only on
 * the file list and the durations file, so all shards agree.
 */
// Vitest reports a file's test time without its import and environment set-up;
// this stands in for that fixed cost of every file.
const FILE_OVERHEAD_MS = 250

export function planShards(
  files: string[],
  durations: Record<string, number>,
  count: number
): string[][] {
  const known = files
    .map((f) => durations[f])
    .filter((d): d is number => Number.isFinite(d) && d > 0)
  const sorted = [...known].sort((a, b) => a - b)
  const fallback = sorted.length ? sorted[Math.floor(sorted.length / 2)] : 1 // the median stands in for a new file
  const weight = (f: string) =>
    FILE_OVERHEAD_MS + (Number.isFinite(durations[f]) && durations[f] > 0 ? durations[f] : fallback)
  const order = [...files].sort((a, b) => weight(b) - weight(a) || (a < b ? -1 : a > b ? 1 : 0))
  const load = new Array<number>(count).fill(0)
  const shards: string[][] = Array.from({ length: count }, () => [])
  for (const f of order) {
    let best = 0
    for (let i = 1; i < count; i++) if (load[i] < load[best]) best = i
    load[best] += weight(f)
    shards[best].push(f)
  }
  return shards
}

function readDurations(): Record<string, number> | null {
  const path = process.env.VITEST_DURATIONS
  if (!path) return null
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'))
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed))
      return parsed as Record<string, number>
  } catch {
    // unreadable: fall back to the default split
  }
  return null
}

export default class DurationSequencer extends BaseSequencer {
  async shard(files: TestSpecification[]): Promise<TestSpecification[]> {
    const durations = readDurations()
    if (!durations) return super.shard(files)
    const { index, count } = this.ctx.config.shard!
    const rel = (spec: TestSpecification) =>
      relative(this.ctx.config.root, spec.moduleId).split(sep).join('/')
    const byPath = new Map(files.map((spec) => [rel(spec), spec]))
    const mine = planShards([...byPath.keys()], durations, count)[index - 1]
    return mine.map((p) => byPath.get(p)!)
  }
}
