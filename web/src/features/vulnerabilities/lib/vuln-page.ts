/**
 * Pure helpers of the vulnerability page (api/docs/architecture/vulnerability-page.md):
 * the findings-list links every number opens, the status buckets of the
 * stacked bar, the CVSS vector in words, the exploit signals and the feed
 * freshness. No React here, so each rule has a unit test.
 */

import { parseCvssVector } from '@/lib/cvss'
import {
  FINDINGS_DISPOSITIONED_STATUSES,
  FINDINGS_FIXED_STATUSES,
  FINDINGS_OPEN_STATUSES,
} from '@/features/findings/lib/list-defaults'
import type { StatusTone } from '@/lib/status-colors'
import type { Vulnerability } from '../types'
import type { CveExposure, FeedFreshness } from '../types/exposure'

const CVE_RE = /^CVE-\d{4}-\d{4,19}$/i

/** Whether an id is a CVE id (any case). */
export function isCveId(id: string): boolean {
  return CVE_RE.test(id.trim())
}

/** The findings list filtered by the CVE, plus extra filters (URL params the list reads). */
export function cveFindingsHref(cve: string, extra: Record<string, string> = {}): string {
  const p = new URLSearchParams({ cve_id: cve, ...extra })
  return `/findings?${p.toString()}`
}

export type StatusBucketKey =
  'open' | 'fixed' | 'accepted' | 'false_positive' | 'duplicate' | 'other'

export interface StatusBucket {
  key: StatusBucketKey
  count: number
  tone: StatusTone
  /** The findings list showing exactly this segment. */
  href: string
}

const OPEN = new Set<string>(FINDINGS_OPEN_STATUSES)
const FIXED = new Set<string>(FINDINGS_FIXED_STATUSES)
const DISPOSITIONED = new Set<string>(FINDINGS_DISPOSITIONED_STATUSES)

/**
 * The status bar's segments, in workflow order, zero segments dropped. Open
 * and Fixed are the list's lenses; each disposition is its own status; any
 * other status (a pentest draft) is "Other" and opens the unfiltered list.
 */
export function statusBuckets(cve: string, byStatus: Record<string, number>): StatusBucket[] {
  const sum = { open: 0, fixed: 0, accepted: 0, false_positive: 0, duplicate: 0, other: 0 }
  for (const [status, n] of Object.entries(byStatus)) {
    if (OPEN.has(status)) sum.open += n
    else if (FIXED.has(status)) sum.fixed += n
    else if (DISPOSITIONED.has(status))
      sum[status as 'accepted' | 'false_positive' | 'duplicate'] += n
    else sum.other += n
  }
  const all: StatusBucket[] = [
    { key: 'open', count: sum.open, tone: 'open', href: cveFindingsHref(cve, { state: 'open' }) },
    {
      key: 'fixed',
      count: sum.fixed,
      tone: 'resolved',
      href: cveFindingsHref(cve, { state: 'fixed' }),
    },
    {
      key: 'accepted',
      count: sum.accepted,
      tone: 'accepted',
      href: cveFindingsHref(cve, { status: 'accepted' }),
    },
    {
      key: 'false_positive',
      count: sum.false_positive,
      tone: 'closed',
      href: cveFindingsHref(cve, { status: 'false_positive' }),
    },
    {
      key: 'duplicate',
      count: sum.duplicate,
      tone: 'closed',
      href: cveFindingsHref(cve, { status: 'duplicate' }),
    },
    { key: 'other', count: sum.other, tone: 'triage', href: cveFindingsHref(cve) },
  ]
  return all.filter((b) => b.count > 0)
}

/** A CVSS metric in words: an i18n key under vulnPage.cvss and its English text. */
export interface CvssWord {
  key: string
  fallback: string
}

/**
 * The few CVSS base metrics a person reads first, in words: attack vector,
 * privileges, user interaction and the worst impact. Unknown or partial
 * vectors give the words they can.
 */
export function cvssWords(vector: string | undefined): CvssWord[] {
  if (!vector) return []
  const parsed = parseCvssVector(vector)
  if (!parsed) return []
  const m = parsed.metrics
  const out: CvssWord[] = []
  const av: Record<string, CvssWord> = {
    N: { key: 'network', fallback: 'network' },
    A: { key: 'adjacent', fallback: 'adjacent network' },
    L: { key: 'local', fallback: 'local' },
    P: { key: 'physical', fallback: 'physical' },
  }
  if (m.AV && av[m.AV]) out.push(av[m.AV])
  if (m.PR === 'N') out.push({ key: 'noAuth', fallback: 'no auth' })
  else if (m.PR === 'L') out.push({ key: 'lowPrivileges', fallback: 'low privileges' })
  else if (m.PR === 'H') out.push({ key: 'highPrivileges', fallback: 'high privileges' })
  if (m.UI === 'N') out.push({ key: 'noUserAction', fallback: 'no user action' })
  else if (m.UI && m.UI !== 'N') out.push({ key: 'userAction', fallback: 'user action' })
  // v3: C/I/A; v4: VC/VI/VA.
  const impacts = [m.C, m.I, m.A, m.VC, m.VI, m.VA].filter(Boolean)
  if (impacts.includes('H')) out.push({ key: 'highImpact', fallback: 'high impact' })
  else if (impacts.includes('L')) out.push({ key: 'lowImpact', fallback: 'low impact' })
  return out
}

export type ExploitSignalKey =
  'kev' | 'ransomware' | 'weaponized' | 'functional' | 'poc' | 'epssHigh'

/**
 * The exploit signals the catalog holds, strongest first. Each is a fact a
 * feed or scanner states; nothing is guessed.
 */
export function exploitSignals(v: Vulnerability | undefined): ExploitSignalKey[] {
  if (!v) return []
  const out: ExploitSignalKey[] = []
  if (v.cisa_kev) out.push('kev')
  if (v.cisa_kev?.ransomware_use?.toLowerCase() === 'known') out.push('ransomware')
  if (v.exploit_maturity === 'weaponized') out.push('weaponized')
  else if (v.exploit_maturity === 'functional') out.push('functional')
  else if (v.exploit_maturity === 'poc' || v.exploit_available) out.push('poc')
  if ((v.epss_score ?? 0) >= 0.1) out.push('epssHigh')
  return out
}

/** A feed older than this (hours) is shown as stale. */
export const FEED_STALE_HOURS = 48

/** Whether a feed's last sync is missing or older than FEED_STALE_HOURS. */
export function feedStale(feed: FeedFreshness, now: number = Date.now()): boolean {
  if (!feed.last_sync_at || feed.status === 'failed') return true
  return now - new Date(feed.last_sync_at).getTime() > FEED_STALE_HOURS * 3600_000
}

/** The single fixed version to show in the header and intel row, if one is clear. */
export function headlineFix(
  exposure: CveExposure | undefined,
  v: Vulnerability | undefined
): string | undefined {
  const up = exposure?.upgrades ?? []
  if (up.length === 1) return up[0].target
  const fixed = v?.fixed_versions ?? []
  if (up.length === 0 && fixed.length === 1) return fixed[0]
  return undefined
}

/** Percent share of n in total, 0 when total is 0, never below 1 for a positive n. */
export function share(n: number, total: number): number {
  if (total <= 0 || n <= 0) return 0
  return Math.max(1, Math.round((n / total) * 100))
}
