/**
 * The Review step's refused targets, grouped by what would fix them
 * (RFC-054 §6.4): one group per reason, so 281 refusals read as three or
 * four decisions with one action each instead of 281 rows. Pure: the codes,
 * rules and fixes are the server's; nothing here decides whether a target
 * may be scanned.
 */

import type { ApiScopeCheckResult, ApiScopeFix } from '@/features/scope'

/** What one group asks the user to do. */
export type RefusalGroupKind =
  | 'proof' // platform sensors (or intrusive probes) need a verified domain
  | 'platform' // only program entries cover it: platform sensors never probe it
  | 'zone' // private address outside every scan zone, or a zone without sensors
  | 'unresolved' // a name with no DNS answer: fix DNS or scan its address
  | 'entry' // the scope entry that covers it is pending, deactivated or expired
  | 'scope' // nothing in scope covers it (or not at this tier / these ports)
  | 'ownership' // excluded, rejected, waiting for review, third party
  | 'access' // outside the caller's data scope
  | 'invalid' // not a valid target, or the platform does not allow it

const KIND_OF_CODE: Record<string, RefusalGroupKind> = {
  proof_required: 'proof',
  program_platform: 'platform',
  unresolved: 'unresolved',
  zone_none: 'zone',
  zone_no_sensor: 'zone',
  zone_sensor_mismatch: 'zone',
  entry_pending: 'entry',
  entry_inactive: 'entry',
  entry_expired: 'entry',
  no_entry: 'scope',
  tier_exceeds: 'scope',
  constrained: 'scope',
  guardrailed: 'scope',
  low_impact: 'scope',
  web_ports_only: 'scope',
  excluded: 'ownership',
  rejected: 'ownership',
  needs_review: 'ownership',
  candidate: 'ownership',
  dependency: 'ownership',
  monitor_only: 'ownership',
  wildcard_only: 'ownership',
  out_of_data_scope: 'access',
  not_an_asset: 'access',
  invalid_target: 'invalid',
  deny_list: 'invalid',
}

/** Display order: what the user can fix in one click first. */
const ORDER: RefusalGroupKind[] = [
  'entry',
  'proof',
  'platform',
  'zone',
  'unresolved',
  'scope',
  'ownership',
  'access',
  'invalid',
]

export interface RefusalGroup {
  /** Stable key (kind, or kind + entry id for entry groups). */
  key: string
  kind: RefusalGroupKind
  /** The refusal code all members share (entry groups: pending/inactive/expired). */
  code: string
  results: ApiScopeCheckResult[]
  /** The covering entry (entry groups). */
  rule?: { id?: string; pattern?: string }
  /** Fixes of the group's first member that act on the whole group. */
  fixes: ApiScopeFix[]
  /** Distinct domains to verify (proof groups). */
  domains: string[]
}

export function refusalKind(code: string | undefined): RefusalGroupKind {
  return KIND_OF_CODE[code ?? ''] ?? 'invalid'
}

/** Fix actions that change one shared thing (an entry), safe to offer once. */
const ENTRY_FIXES = new Set(['approve_entry', 'activate_entry', 'renew_entry'])

/**
 * Groups the refused results. Entry refusals are grouped per covering entry
 * (one Approve or Activate for all the names it covers); the rest per kind.
 */
export function groupRefusals(results: readonly ApiScopeCheckResult[]): RefusalGroup[] {
  const groups = new Map<string, RefusalGroup>()
  for (const r of results) {
    if (r.allowed) continue
    const kind = refusalKind(r.code)
    const key = kind === 'entry' ? `entry:${r.rule?.id ?? r.rule?.pattern ?? r.code}` : kind
    let g = groups.get(key)
    if (!g) {
      g = {
        key,
        kind,
        code: r.code ?? '',
        results: [],
        rule: kind === 'entry' ? r.rule : undefined,
        fixes:
          kind === 'entry' ? (r.fixes ?? []).filter((f) => ENTRY_FIXES.has(f.action ?? '')) : [],
        domains: [],
      }
      groups.set(key, g)
    }
    g.results.push(r)
    if (kind === 'proof') {
      for (const f of r.fixes ?? []) {
        const d = f.action === 'verify_domain' ? (f.domain ?? f.pattern) : undefined
        if (d && !g.domains.includes(d)) g.domains.push(d)
      }
    }
  }
  return [...groups.values()].sort(
    (a, b) => ORDER.indexOf(a.kind) - ORDER.indexOf(b.kind) || b.results.length - a.results.length
  )
}

/** Whether a "Verify <domain>" fix was offered (the caller may verify). */
export function canVerify(g: RefusalGroup): boolean {
  return g.results.some((r) => (r.fixes ?? []).some((f) => f.action === 'verify_domain'))
}

/** Whether switching to the organization's own sensors would help. */
export function ownSensorHelps(g: RefusalGroup): boolean {
  if (g.kind === 'platform') return true
  return (
    g.kind === 'proof' &&
    g.results.some((r) => (r.fixes ?? []).some((f) => f.action === 'use_tenant_sensor'))
  )
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

/**
 * The internal address a zone refusal is about: what the hostname resolved
 * to, or the target itself when it is an address. Undefined otherwise.
 */
export function internalAddressOf(r: ApiScopeCheckResult): string | undefined {
  if (r.resolved && r.resolved.length > 0) return r.resolved[0]
  const t = (r.target ?? '').trim()
  if (IPV4.test(t) || (t.includes(':') && /^[0-9a-f:]+$/i.test(t))) return t
  return undefined
}
