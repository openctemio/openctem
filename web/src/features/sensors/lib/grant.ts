/**
 * Pure helpers of the sensor grant panel (api docs/rfcs/RFC-052 §5).
 */

import type { SensorGrant, UpdateSensorGrantRequest } from '@/lib/api/sensor-grant-hooks'

/** Command types a grant's job types govern (control commands are always allowed). */
export const GRANT_JOB_TYPES = [
  'scan',
  'collect',
  'validate',
  'retest',
  'connector_sync',
  'connector_scan',
  'config_update',
] as const

/** Remote actions a grant may list; pause, resume, drain, cancel and send_manifest are always allowed. */
export const GATED_REMOTE_ACTIONS = ['update', 'rotate_key', 'diagnostics'] as const

export const TIER_LABELS: Record<number, string> = {
  0: 'T0 · passive',
  1: 'T1 · active, non-intrusive',
  2: 'T2 · intrusive',
}

export const TARGET_NETWORK_LABELS: Record<string, string> = {
  any: 'Any network',
  public: 'Internet-facing only',
  none: 'No network targets',
}

export const PROFILE_LABELS: Record<string, string> = {
  'legacy-broad': 'Legacy broad grant',
  'internal-network-scanner': 'Internal network scanner',
  'easm-external': 'External attack surface',
  'authenticated-scanner': 'Authenticated scanner',
  collector: 'Collector',
  'ci-runner': 'CI runner',
  'endpoint-agent': 'Endpoint',
  custom: 'Custom',
}

export function profileLabel(profile: string): string {
  const [base, param] = profile.split(':', 2)
  const label = PROFILE_LABELS[base] ?? profile
  return param ? `${label} (${param})` : label
}

/**
 * A list dimension as people read it: null is no limit ("Any"), [] is
 * nothing ("None"), otherwise the entries.
 */
export function formatGrantList(list: string[] | null | undefined, names?: (v: string) => string) {
  if (list === null || list === undefined) return 'Any'
  if (list.length === 0) return 'None'
  return list.map((v) => (names ? names(v) : v)).join(', ')
}

export function tierLabel(tier: number): string {
  return TIER_LABELS[tier] ?? `T${tier}`
}

/** "a, b\nc" → ["a","b","c"] (trimmed, de-duplicated, sorted). */
export function parseListInput(text: string): string[] {
  const out = text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
  return Array.from(new Set(out)).sort()
}

function listWidened(cur: string[] | null, next: string[] | null): boolean {
  if (cur === null) return false
  if (next === null) return true
  return next.some((n) => !cur.includes(n))
}

const NETWORK_RANK: Record<string, number> = { none: 0, public: 1, any: 2 }

/**
 * The dimensions on which `next` allows something `cur` does not. A hint for
 * the form only (the server decides, with exact CIDR containment); an empty
 * result means the change only narrows.
 */
export function widenedDimensions(cur: SensorGrant, next: UpdateSensorGrantRequest): string[] {
  const out: string[] = []
  if (cur.trust_level !== 'trusted' && next.trust_level === 'trusted') out.push('trust level')
  if (listWidened(cur.job_types, next.job_types)) out.push('job types')
  if (listWidened(cur.zone_ids, next.zone_ids)) out.push('zones')
  if (listWidened(cur.tools, next.tools)) out.push('tools')
  if (listWidened(cur.capabilities, next.capabilities)) out.push('capabilities')
  if (next.tier_ceiling > cur.tier_ceiling) out.push('tier ceiling')
  if ((NETWORK_RANK[next.target_network] ?? 2) > (NETWORK_RANK[cur.target_network] ?? 2))
    out.push('target network')
  const curAny = cur.target_cidrs === null && cur.target_domains === null
  const nextAny = next.target_cidrs === null && next.target_domains === null
  if (
    !curAny &&
    (nextAny ||
      listWidened(cur.target_cidrs ?? [], next.target_cidrs ?? []) ||
      listWidened(cur.target_domains ?? [], next.target_domains ?? []))
  )
    out.push('target scope')
  if (next.allow_credentials && !cur.allow_credentials) out.push('credentials')
  if (next.allow_push_ingest && !cur.allow_push_ingest) out.push('push ingest')
  if (listWidened(cur.remote_actions ?? [], next.remote_actions ?? [])) out.push('remote actions')
  return out
}
