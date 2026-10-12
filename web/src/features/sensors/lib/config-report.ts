/**
 * The sensor setup report (research/26-sensor-config-doctor.md §4.6–§4.8):
 * the checks a sensor runs on its own configuration, explained and given
 * fixes by the platform catalog. These helpers order and group the checks,
 * pick the fix formats to show, and decide which docs links are safe.
 *
 * Everything the sensor wrote (summary, excerpt, observed values, the id of
 * a check the catalog does not know) is an untrusted claim: the components
 * render it only as text. Fix snippets and titles come from the platform
 * catalog (the API), never from the sensor.
 */

import type {
  SensorConfigCheck,
  SensorConfigCheckGroup,
  SensorConfigCheckStatus,
  SensorConfigHealth,
} from '@/lib/api/sensor-types'
import type { DetailCheckStatus } from '@/features/shared'
import { safeHref } from '@/lib/safe-href'
import { DOCS_ORIGIN } from '@/lib/docs-links'

type Tone = 'muted' | 'info' | 'warning' | 'destructive' | 'success'

/** Health as a tag: label key, English fallback and tone. */
export const CONFIG_HEALTH_META: Record<
  SensorConfigHealth,
  { key: string; label: string; tone: Tone }
> = {
  ok: { key: 'sensors.setup.health.ok', label: 'Setup OK', tone: 'success' },
  attention: {
    key: 'sensors.setup.health.attention',
    label: 'Setup needs attention',
    tone: 'warning',
  },
  impaired: { key: 'sensors.setup.health.impaired', label: 'Setup impaired', tone: 'destructive' },
  blocked: { key: 'sensors.setup.health.blocked', label: 'Setup blocked', tone: 'destructive' },
  unknown: { key: 'sensors.setup.health.unknown', label: 'Setup unknown', tone: 'muted' },
}

/** The health values the fleet calls out: ok and unknown show nothing. */
export function configHealthNeedsAttention(
  health: string | null | undefined
): health is 'attention' | 'impaired' | 'blocked' {
  return health === 'attention' || health === 'impaired' || health === 'blocked'
}

export function configHealthMeta(health: string | null | undefined) {
  return (
    CONFIG_HEALTH_META[(health ?? 'unknown') as SensorConfigHealth] ?? CONFIG_HEALTH_META.unknown
  )
}

/** A check status as the shared checklist icon (detail-checklist). */
export const CHECK_STATUS_ICON: Record<SensorConfigCheckStatus, DetailCheckStatus> = {
  pass: 'ok',
  warn: 'warning',
  fail: 'critical',
  error: 'critical',
  skip: 'info',
}

export const CHECK_STATUS_LABEL: Record<SensorConfigCheckStatus, { key: string; label: string }> = {
  pass: { key: 'sensors.setup.status.pass', label: 'Passed' },
  warn: { key: 'sensors.setup.status.warn', label: 'Warning' },
  fail: { key: 'sensors.setup.status.fail', label: 'Failed' },
  error: { key: 'sensors.setup.status.error', label: 'Check error' },
  skip: { key: 'sensors.setup.status.skip', label: 'Skipped' },
}

export function checkStatusIcon(status: string): DetailCheckStatus {
  return CHECK_STATUS_ICON[status as SensorConfigCheckStatus] ?? 'info'
}

/** Groups in display order (the API's closed set). */
export const CHECK_GROUPS: { group: SensorConfigCheckGroup; label: string }[] = [
  { group: 'platform', label: 'Platform' },
  { group: 'identity', label: 'Identity' },
  { group: 'policy', label: 'Policy' },
  { group: 'tools', label: 'Tools' },
  { group: 'content', label: 'Content' },
  { group: 'network', label: 'Network' },
  { group: 'storage', label: 'Storage' },
  { group: 'runtime', label: 'Runtime' },
  { group: 'config', label: 'Configuration' },
  { group: 'connector', label: 'Connector' },
]

const STATUS_RANK: Record<string, number> = { fail: 0, error: 1, warn: 2, skip: 3, pass: 4 }

export interface CheckGroup {
  group: string
  label: string
  checks: SensorConfigCheck[]
  /** The worst status in the group (for ordering and the group's icon). */
  worst: string
}

/**
 * The checks grouped by area, groups with a failing check first, then in
 * catalog order; within a group fail, error, warn, skip, pass, then id.
 * A group outside the closed set lands in "Other" at the end.
 */
export function groupChecks(checks: SensorConfigCheck[]): CheckGroup[] {
  const known = new Map<string, number>(CHECK_GROUPS.map((g, i) => [g.group, i]))
  const byGroup = new Map<string, SensorConfigCheck[]>()
  for (const c of checks) {
    const g = known.has(c.group) ? c.group : 'other'
    const list = byGroup.get(g) ?? []
    list.push(c)
    byGroup.set(g, list)
  }
  const rank = (s: string) => STATUS_RANK[s] ?? 5
  const groups: CheckGroup[] = []
  for (const [group, list] of byGroup) {
    list.sort((a, b) => rank(a.status) - rank(b.status) || a.id.localeCompare(b.id))
    groups.push({
      group,
      label: CHECK_GROUPS.find((g) => g.group === group)?.label ?? 'Other',
      checks: list,
      worst: list[0]?.status ?? 'pass',
    })
  }
  return groups.sort(
    (a, b) =>
      rank(a.worst) - rank(b.worst) || (known.get(a.group) ?? 99) - (known.get(b.group) ?? 99)
  )
}

/** Fix formats in tab order, with labels. Only these are shown. */
export const FIX_FORMATS: { key: string; label: string }[] = [
  { key: 'compose', label: 'Compose' },
  { key: 'docker', label: 'docker run' },
  { key: 'kubernetes', label: 'Kubernetes' },
  { key: 'helm', label: 'Helm' },
  { key: 'systemd', label: 'systemd' },
  { key: 'env', label: 'Env' },
]

/** The fix formats a check carries (non-empty strings only), in tab order. */
export function fixFormats(fix: SensorConfigCheck['fix']): string[] {
  if (!fix || typeof fix !== 'object') return []
  return FIX_FORMATS.filter((f) => {
    const v = fix[f.key]
    return typeof v === 'string' && v.trim() !== ''
  }).map((f) => f.key)
}

/** The format to open first: the one matching how the sensor runs (§4.7). */
const PREFERRED_BY_RUNTIME: Record<string, string[]> = {
  docker: ['compose', 'docker', 'env'],
  kubernetes: ['helm', 'kubernetes', 'env'],
  systemd: ['systemd', 'env'],
  binary: ['env', 'systemd'],
}

export function defaultFixFormat(formats: string[], runtimeKind?: string): string | undefined {
  for (const f of PREFERRED_BY_RUNTIME[runtimeKind ?? ''] ?? []) {
    if (formats.includes(f)) return f
  }
  return formats[0]
}

/**
 * The docs link as an href, or null when it is not one we link to: only an
 * https URL on docs.openctem.io or a same-origin path ("/docs/…"), after the
 * shared `safeHref` encoder (no other scheme, no `//host` or `/\host`, no
 * control or bidi characters). Credentials and ports are refused too.
 */
export function safeDocsHref(url: string | null | undefined): string | null {
  const safe = safeHref(url)
  if (!safe) return null
  if (safe.startsWith('/') && !safe.startsWith('//')) return safe
  if (typeof url !== 'string' || !url.startsWith(`${DOCS_ORIGIN}/`)) return null
  try {
    const u = new URL(safe)
    if (u.origin !== DOCS_ORIGIN || u.username || u.password) return null
    return u.href
  } catch {
    return null
  }
}

/** Counts in the order shown in the header, zeros left out (pass always shown). */
export function countParts(
  counts: Partial<Record<SensorConfigCheckStatus, number>> | undefined
): { status: SensorConfigCheckStatus; n: number }[] {
  const order: SensorConfigCheckStatus[] = ['fail', 'error', 'warn', 'skip', 'pass']
  return order
    .map((status) => ({ status, n: counts?.[status] ?? 0 }))
    .filter((p) => p.n > 0 || p.status === 'pass')
}
