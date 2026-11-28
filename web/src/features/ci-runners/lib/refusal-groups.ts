/**
 * Refused CI jobs grouped by what refused them. A pipeline that keeps
 * running on a branch no rule admits is refused on every push: shown one
 * card per job, the same repository, ref, rule and fix filled the list. One
 * group per repository, ref, event, provider, pipeline file and rule set,
 * with how many jobs it holds and when the last one came.
 */

import type { CITokenRefusal } from '../types'

export interface RefusalGroup {
  key: string
  /** The newest refusal of the group: its fields and fixes stand for all. */
  refusal: CITokenRefusal
  count: number
  /** When the newest job of the group was refused. */
  lastAt?: string
}

/** How many groups a list shows before "Show more", and how many more each press adds. */
export const REFUSAL_GROUPS_PAGE = 5

function groupKey(r: CITokenRefusal): string {
  return JSON.stringify([
    r.provider ?? '',
    r.repository ?? '',
    r.ref ?? '',
    r.event ?? '',
    r.workflow_definition ?? '',
    [...(r.reasons ?? [])].sort(),
    // The message carries the pipeline file a workflow refusal names.
    (r.reasons ?? []).includes('workflow_not_allowed') ? (r.message ?? '') : '',
  ])
}

const time = (at?: string) => (at ? Date.parse(at) || 0 : 0)

/** Groups identical refusals, newest group first; each group keeps its newest refusal. */
export function groupRefusals(list: CITokenRefusal[]): RefusalGroup[] {
  const groups = new Map<string, RefusalGroup>()
  for (const r of list) {
    const key = groupKey(r)
    const g = groups.get(key)
    if (!g) {
      groups.set(key, { key, refusal: r, count: 1, lastAt: r.at })
      continue
    }
    g.count++
    if (time(r.at) > time(g.lastAt)) {
      g.refusal = r
      g.lastAt = r.at
    }
  }
  return [...groups.values()].sort((a, b) => time(b.lastAt) - time(a.lastAt))
}
