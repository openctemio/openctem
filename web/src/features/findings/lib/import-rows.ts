/**
 * The rows of the Imports list (findings/imports): what each receipt changed,
 * whether its processing needs a look, and the folding of the runs that
 * received no findings at all.
 *
 * Asset-discovery tools (subfinder, dnsx) leave a receipt per run with every
 * finding count at zero. Listed one by one they repeat the same row many
 * times; the list folds the runs of one tool and source kind that received no
 * findings into one row that names how many runs it holds, and that row opens
 * every run (nothing is dropped). A run that did anything to findings, one
 * that failed or is still running, and a run with problems never fold.
 */

import type { ReceiptResponse } from '../api/receipts-api'

/** A list row: one receipt, or the folded runs that received no findings. */
export interface ImportRow {
  id: string
  /** The receipt the row shows (for a folded row: the newest of its runs). */
  receipt: ReceiptResponse
  /** Set on a folded row: every run it holds, newest first (two or more). */
  runs?: ReceiptResponse[]
}

/**
 * The processing state worth showing, or null for a completed receipt without
 * problems. "partial" is a completed receipt that could not store some of its
 * findings or reported problems.
 */
export function receiptIssue(r: ReceiptResponse): string | null {
  const status = r.status ?? ''
  if (status && status !== 'completed') return status
  if ((r.counts?.failed ?? 0) > 0 || (r.errors?.length ?? 0) > 0) return 'partial'
  return null
}

/** What a receipt did to findings and assets, as plain numbers. */
export interface ImportChange {
  received: number
  created: number
  closed: number
  reactivated: number
  suppressed: number
  updated: number
  notStored: number
  assets: number
}

export function importChange(r: ReceiptResponse): ImportChange {
  const c = r.counts
  return {
    received: r.received ?? 0,
    created: c?.created ?? 0,
    closed: c?.closed ?? 0,
    reactivated: c?.reactivated ?? 0,
    suppressed: c?.suppressed ?? 0,
    updated: c?.updated ?? 0,
    notStored: (c?.skipped ?? 0) + (c?.failed ?? 0),
    assets: (r.assets?.created ?? 0) + (r.assets?.updated ?? 0),
  }
}

/** The sum of the changes of several runs (a folded row). */
export function sumChanges(runs: readonly ReceiptResponse[]): ImportChange {
  const total: ImportChange = {
    received: 0,
    created: 0,
    closed: 0,
    reactivated: 0,
    suppressed: 0,
    updated: 0,
    notStored: 0,
    assets: 0,
  }
  for (const r of runs) {
    const c = importChange(r)
    for (const k of Object.keys(total) as (keyof ImportChange)[]) total[k] += c[k]
  }
  return total
}

function closedByCoverage(r: ReceiptResponse): number {
  return Object.values(r.closing?.closed ?? {}).reduce((a, v) => a + (v ?? 0), 0)
}

/**
 * A completed run without problems that received no findings and changed no
 * finding (it may have found assets).
 */
export function isNoFindingsRun(r: ReceiptResponse): boolean {
  if (receiptIssue(r) !== null) return false
  const c = importChange(r)
  return (
    c.received === 0 &&
    c.created === 0 &&
    c.closed === 0 &&
    c.reactivated === 0 &&
    c.suppressed === 0 &&
    c.updated === 0 &&
    c.notStored === 0 &&
    closedByCoverage(r) === 0 &&
    !Object.values(r.outcomes ?? {}).some((v) => (v ?? 0) > 0)
  )
}

/**
 * Folds the runs of one tool and source kind that received no findings into
 * one row, placed where the newest of them is. A lone such run stays a row of
 * its own. Every other receipt keeps its row and its order.
 */
export function foldNoFindingRuns(rows: readonly ReceiptResponse[]): ImportRow[] {
  const key = (r: ReceiptResponse) => `${r.source?.kind ?? ''}\u0000${r.tool ?? ''}`
  const groups = new Map<string, ReceiptResponse[]>()
  for (const r of rows) {
    if (!isNoFindingsRun(r)) continue
    const k = key(r)
    const list = groups.get(k)
    if (list) list.push(r)
    else groups.set(k, [r])
  }
  const placed = new Set<string>()
  const out: ImportRow[] = []
  for (const r of rows) {
    const runs = isNoFindingsRun(r) ? groups.get(key(r)) : undefined
    if (runs && runs.length > 1) {
      const k = key(r)
      if (placed.has(k)) continue
      placed.add(k)
      out.push({ id: `runs:${r.id ?? k}`, receipt: r, runs })
      continue
    }
    out.push({ id: r.id ?? '', receipt: r })
  }
  return out
}
