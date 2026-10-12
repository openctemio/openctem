/**
 * Completing a remediation campaign while findings are still open.
 *
 * Progress is `resolved_count / finding_count` (closed findings over all the
 * findings in scope, api/docs/architecture/remediation-campaigns.md), and
 * completing does not change it: a campaign completed with 0 of 4 findings
 * closed reads "Completed, 0%". That is allowed (the work may be tracked
 * elsewhere), but never silently: the console asks first and says how many
 * findings are still open.
 */

import { get } from '@/lib/api/client'

/** The counts the API keeps on a campaign. */
export interface CampaignCounts {
  finding_count: number
  resolved_count: number
}

export interface CompletionWarning {
  /** Findings in scope that are not closed yet, across all the campaigns. */
  open: number
  /** All findings in scope, across all the campaigns. */
  total: number
  /** How many of the campaigns still have open findings. */
  campaigns: number
}

/** Findings in scope that are not closed. Never negative. */
export function openFindingCount(c: CampaignCounts): number {
  const total = Number.isFinite(c.finding_count) ? c.finding_count : 0
  const resolved = Number.isFinite(c.resolved_count) ? c.resolved_count : 0
  return Math.max(0, total - resolved)
}

/** Null when nothing is left open, so completing needs no confirmation. */
export function completionWarning(counts: CampaignCounts[]): CompletionWarning | null {
  let open = 0
  let total = 0
  let campaigns = 0
  for (const c of counts) {
    const o = openFindingCount(c)
    open += o
    total += Math.max(0, c.finding_count || 0)
    if (o > 0) campaigns += 1
  }
  return open > 0 ? { open, total, campaigns } : null
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

/** The sentence the confirmation shows, e.g. "4 of 4 findings are still open." */
export function completionWarningText(w: CompletionWarning, selected = 1): string {
  const verb = w.open === 1 ? 'is' : 'are'
  if (selected <= 1) {
    return `${w.open} of ${plural(w.total, 'finding', 'findings')} ${verb} still open.`
  }
  return `${w.open} of ${plural(w.total, 'finding', 'findings')} in ${plural(w.campaigns, 'task', 'tasks')} ${verb} still open.`
}

/** Progress as a whole percentage for display (the API sends e.g. 33.333…). */
export function progressPercent(progress: number | null | undefined): number {
  const p = Number(progress)
  if (!Number.isFinite(p)) return 0
  return Math.min(100, Math.max(0, Math.round(p)))
}

/**
 * The live counts of these campaigns. `GET /campaigns/{id}` recomputes them
 * from the findings, while a list row may be up to one reconcile old. A
 * campaign that cannot be fetched keeps its `fallback` counts, so a failed
 * read never skips the confirmation.
 */
export async function fetchLiveCampaignCounts(
  ids: string[],
  fallback: Record<string, CampaignCounts | undefined> = {}
): Promise<CampaignCounts[]> {
  const results = await Promise.allSettled(
    ids.map((id) => get<CampaignCounts>(`/api/v1/remediation/campaigns/${encodeURIComponent(id)}`))
  )
  const out: CampaignCounts[] = []
  results.forEach((r, i) => {
    if (r.status === 'fulfilled' && r.value) out.push(r.value)
    else {
      const f = fallback[ids[i]]
      if (f) out.push(f)
    }
  })
  return out
}
