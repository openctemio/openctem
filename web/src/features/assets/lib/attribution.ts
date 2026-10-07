/**
 * Asset attribution (RFC-036 §6.4): whether the platform believes an asset
 * is the organization's, and why. Pure helpers shared by the attribution
 * section and its tests.
 */

export type AttributionState =
  'confirmed' | 'needs_review' | 'candidate' | 'dependency' | 'monitor_only' | 'rejected'

export interface AttributionEvidence {
  rule: string
  technique: string
  source: string
  weight: number
  observed?: Record<string, unknown>
  first_observed_at: string
  last_observed_at: string
}

/** GET /api/v1/assets/{id}/attribution */
export interface AssetAttribution {
  state: AttributionState
  confidence: number
  reason?: string
  /** false: a legacy asset without a record (counts as confirmed). */
  recorded: boolean
  human_decided: boolean
  active_checks_allowed: boolean
  /**
   * Why scans skip the asset when active_checks_allowed is false: its state,
   * `rejected` also for a name under a rejected name, or `unattributed` (no
   * record, and no scope target, seed or verified domain covers it).
   */
  active_checks_blocked_by?: AttributionState | 'unattributed' | 'out_of_scope'
  decided_at?: string
  evidence: AttributionEvidence[]
}

/** The decisions a person can take (PUT /assets/{id}/attribution). */
export type AttributionDecision = Exclude<AttributionState, 'candidate'>

export const ATTRIBUTION_STATE_LABEL: Record<AttributionState, string> = {
  confirmed: 'Confirmed',
  needs_review: 'Needs review',
  candidate: 'Candidate',
  dependency: 'Dependency',
  monitor_only: 'Monitor only',
  rejected: 'Not ours',
}

/** Theme-token tint per state (ui-style-contract §6). */
export const ATTRIBUTION_STATE_CLASS: Record<AttributionState, string> = {
  confirmed: 'bg-success/15 text-success',
  needs_review: 'bg-warning/15 text-warning',
  candidate: 'bg-muted text-muted-foreground',
  dependency: 'bg-info/15 text-info',
  monitor_only: 'bg-info/15 text-info',
  rejected: 'bg-destructive/15 text-destructive',
}

const TECHNIQUE_LABEL: Record<string, string> = {
  cert_transparency: 'Certificate Transparency',
}

const SOURCE_LABEL: Record<string, string> = {
  'crt.sh': 'crt.sh',
  certspotter: 'Cert Spotter',
}

/**
 * One evidence row as a sentence a reviewer can check, for example
 * "Under verified domain acme.com — seen in Certificate Transparency (crt.sh)
 * since 5 Jan 2026".
 */
export function describeEvidence(e: AttributionEvidence): string {
  const root = typeof e.observed?.root === 'string' ? e.observed.root : ''
  let what: string
  switch (e.rule) {
    case 'fqdn_under_verified_root':
      what = root ? `Under verified domain ${root}` : 'Under a verified domain'
      break
    case 'fqdn_under_asserted_root':
      what = root
        ? `Under ${root}, a domain you listed but have not verified`
        : 'Under a domain you listed but have not verified'
      break
    case 'tenant_scanned':
      what = 'A target your organization scanned'
      break
    case 'tenant_scan_discovered':
      what = 'Found by a scan your organization ran (not one of its targets)'
      break
    default:
      what = e.rule.replace(/_/g, ' ')
  }
  const technique = TECHNIQUE_LABEL[e.technique] ?? e.technique.replace(/_/g, ' ')
  const source = SOURCE_LABEL[e.source] ?? e.source
  const first = typeof e.observed?.first_seen === 'string' ? e.observed.first_seen : ''
  const since = first ? ` since ${formatDay(first)}` : ''
  return `${what} — seen in ${technique} (${source})${since}`
}

function formatDay(iso: string): string {
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return iso
  return new Date(t).toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  })
}

/** The rules that put a name in the review queue, in words (reason filter). */
export const REVIEW_REASON_LABEL: Record<string, string> = {
  fqdn_under_verified_root: 'Under a verified domain',
  fqdn_under_asserted_root: 'Under a domain you listed, not verified',
  tenant_scanned: 'A target your organization scanned',
  tenant_scan_discovered: 'Found by one of your scans',
  matches_scope_target: 'Covered by a scope entry',
}

export function reviewReasonLabel(reason: string): string {
  return REVIEW_REASON_LABEL[reason] ?? reason.replace(/_/g, ' ')
}

/** What a scan does with this asset, in words. */
export function scanStanding(
  a: Pick<AssetAttribution, 'active_checks_allowed' | 'state' | 'active_checks_blocked_by'>
): string {
  if (a.active_checks_allowed) return 'Scans can reach this asset.'
  if (a.active_checks_blocked_by === 'unattributed')
    return 'Scans skip this asset: no scope target, seed or verified domain covers it. Add it to Scoping › Targets.'
  if (a.active_checks_blocked_by === 'out_of_scope')
    return 'Scans skip this asset: it is confirmed as yours, but no scope target, seed or verified domain covers it. Add it to Scoping › Targets to scan it.'
  if (a.active_checks_blocked_by === 'rejected' && a.state !== 'rejected')
    return 'Scans skip this asset: a name it sits under was marked not yours.'
  if (a.state === 'needs_review' || a.state === 'candidate')
    return 'Scans skip this asset until its ownership is confirmed.'
  return 'Scans skip this asset; it is watched passively only.'
}

/** The decisions to offer for a state (never the state it is already in). */
export function decisionsFor(state: AttributionState): AttributionDecision[] {
  const all: AttributionDecision[] = ['confirmed', 'rejected', 'dependency', 'monitor_only']
  return all.filter((d) => d !== state)
}
