/**
 * What the console knows about the security overview's checks. The server
 * sends ids, statuses, counts and links only; every title and explanation is
 * a dictionary key `securityOverview.check.<id>.title` and
 * `securityOverview.check.<id>.desc.<status>` (en and vi).
 */

export type CheckStatus = 'risk' | 'warn' | 'pass' | 'info'

/** Groups in display order; ids match the API's `group`. */
export const CHECK_GROUPS = [
  'sign_in',
  'people',
  'credentials',
  'scanning',
  'organization',
] as const

export type CheckGroup = (typeof CHECK_GROUPS)[number]

/** The statuses each known check can take (one explanation per status). */
export const CHECK_STATUSES: Record<string, CheckStatus[]> = {
  'sign_in.mfa_admins_required': ['pass', 'risk'],
  'sign_in.admins_without_mfa': ['pass', 'risk'],
  'sign_in.email_verification': ['pass', 'warn'],
  'sign_in.ip_allowlist': ['pass', 'info'],
  'people.dormant_members': ['pass', 'warn'],
  'people.join_requests': ['pass', 'warn'],
  'credentials.api_keys_expiring': ['pass', 'warn'],
  'credentials.api_keys_unused': ['pass', 'warn'],
  'credentials.scim_tokens_unused': ['pass', 'warn', 'info'],
  'scanning.sensor_opt_ins': ['pass', 'warn'],
  'scanning.private_target_policy': ['pass', 'info'],
  'organization.verified_domain': ['pass', 'info'],
  'organization.support_access': ['pass', 'warn'],
}

/** Worst first, so what to fix leads each group. */
const STATUS_ORDER: Record<CheckStatus, number> = { risk: 0, warn: 1, info: 2, pass: 3 }

export interface OverviewCheck {
  id: string
  group: string
  status: CheckStatus
  count?: number
  link: string
}

/** Normalise the API checks (every field optional in the contract). */
export function normalizeChecks(
  checks: ReadonlyArray<{
    id?: string
    group?: string
    status?: string
    count?: number
    link?: string
  }>
): OverviewCheck[] {
  const out: OverviewCheck[] = []
  for (const c of checks) {
    if (!c.id || !c.group) continue
    const status = (c.status ?? 'info') as CheckStatus
    if (!(status in STATUS_ORDER)) continue
    out.push({ id: c.id, group: c.group, status, count: c.count, link: c.link ?? '' })
  }
  return out
}

/** Checks per group in display order, worst first; unknown groups last. */
export function groupChecks(checks: OverviewCheck[]): Array<[string, OverviewCheck[]]> {
  const byGroup = new Map<string, OverviewCheck[]>()
  for (const c of checks) {
    const list = byGroup.get(c.group) ?? []
    list.push(c)
    byGroup.set(c.group, list)
  }
  const known = CHECK_GROUPS.filter((g) => byGroup.has(g))
  const unknown = [...byGroup.keys()].filter(
    (g) => !(CHECK_GROUPS as readonly string[]).includes(g)
  )
  return [...known, ...unknown].map((g) => [
    g,
    // Array.prototype.sort is stable: the server's order breaks ties.
    [...(byGroup.get(g) ?? [])].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]),
  ])
}

/** Only in-app paths are links: a value from the API is never an off-site URL. */
export function safeInternalLink(link: string): string | null {
  return link.startsWith('/') && !link.startsWith('//') ? link : null
}
