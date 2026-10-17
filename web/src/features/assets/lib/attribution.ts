/**
 * Asset attribution (RFC-036 §6.4): whether the platform believes an asset
 * is the organization's, and why. Pure helpers shared by the attribution
 * section and its tests.
 */

export type AttributionState =
  | 'confirmed'
  | 'discovered'
  | 'needs_review'
  | 'candidate'
  | 'dependency'
  | 'monitor_only'
  | 'rejected'

export interface AttributionEvidence {
  rule: string
  technique: string
  source: string
  /** A person-readable source: the sensor's name for "sensor:<id>" (review queue). */
  source_label?: string
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
  active_checks_blocked_by?:
    AttributionState | 'unattributed' | 'out_of_scope' | 'wildcard_only' | 'guardrailed'
  decided_at?: string
  evidence: AttributionEvidence[]
  /**
   * May scans reach it (RFC-054 §6.6): in_scope, out_of_scope, internal
   * (routed by a scan zone) or not_applicable (cloud
   * resources). Older API responses leave it out.
   */
  scope_status?: 'in_scope' | 'out_of_scope' | 'internal' | 'not_applicable' | string
  /** The organization's scope entry, seed or verified domain that covers it. */
  covered_by?: { kind?: string; id?: string; pattern?: string; proof?: string }
  /** The refusal code (RFC-054 §6.5) when active checks are blocked. */
  blocked_code?: string
  /**
   * Only on the PUT response: the scope entries a confirmation added for the
   * asset's exact name (skipped: why none were tried).
   */
  scope?: {
    skipped?: string
    entries: {
      asset_id?: string
      name?: string
      pattern?: string
      target_type?: string
      target_id?: string
      status?: string
      outcome: 'added' | 'exists' | 'covered' | 'refused'
      code?: string
    }[]
  }
}

/** The decisions a person can take (PUT /assets/{id}/attribution). */
export type AttributionDecision = Exclude<AttributionState, 'candidate'>

/** A translator as `useTranslation()` returns it. */
export type AttributionT = (
  key: string,
  fallback?: string,
  vars?: Record<string, string | number>
) => string

const STATE_LABEL: Record<AttributionState, [string, string]> = {
  confirmed: ['assets.attribution.state.confirmed', 'Confirmed'],
  discovered: ['assets.attribution.state.discovered', 'Discovered'],
  needs_review: ['assets.attribution.state.needsReview', 'Needs review'],
  candidate: ['assets.attribution.state.candidate', 'Candidate'],
  dependency: ['assets.attribution.state.dependency', 'Dependency'],
  monitor_only: ['assets.attribution.state.monitorOnly', 'Monitor only'],
  rejected: ['assets.attribution.state.rejected', 'Not ours'],
}

/** The state in words. */
export function attributionStateLabel(t: AttributionT, state: AttributionState): string {
  const [key, fallback] = STATE_LABEL[state] ?? ['', state]
  return key ? t(key, fallback) : String(state).replace(/_/g, ' ')
}

/** Theme-token tint per state (ui-style-contract §6). */
export const ATTRIBUTION_STATE_CLASS: Record<AttributionState, string> = {
  confirmed: 'bg-success/15 text-success',
  discovered: 'bg-muted text-foreground',
  needs_review: 'bg-warning/15 text-warning',
  candidate: 'bg-muted text-muted-foreground',
  dependency: 'bg-info/15 text-info',
  monitor_only: 'bg-info/15 text-info',
  rejected: 'bg-destructive/15 text-destructive',
}

/**
 * One evidence row as a sentence a reviewer can check, for example
 * "Under verified domain acme.com — seen in Certificate Transparency (crt.sh)
 * since 5 Jan 2026".
 */
export function describeEvidence(t: AttributionT, e: AttributionEvidence): string {
  const root = typeof e.observed?.root === 'string' ? e.observed.root : ''
  let what: string
  switch (e.rule) {
    case 'fqdn_under_verified_root':
      what = root
        ? t('assets.attribution.evidence.verifiedRoot', 'Under verified domain {root}', { root })
        : t('assets.attribution.evidence.verifiedRootAny', 'Under a verified domain')
      break
    case 'fqdn_under_asserted_root':
      what = root
        ? t(
            'assets.attribution.evidence.assertedRoot',
            'Under {root}, a domain you listed but have not verified',
            { root }
          )
        : t(
            'assets.attribution.evidence.assertedRootAny',
            'Under a domain you listed but have not verified'
          )
      break
    case 'tenant_scanned':
      what = t('assets.attribution.evidence.scanned', 'A target your organization scanned')
      break
    case 'tenant_scan_discovered':
      what = t(
        'assets.attribution.evidence.scanDiscovered',
        'Found by a scan your organization ran (not one of its targets)'
      )
      break
    default:
      what = e.rule.replace(/_/g, ' ')
  }
  const technique =
    e.technique === 'cert_transparency'
      ? t('assets.attribution.technique.certTransparency', 'Certificate Transparency')
      : e.technique.replace(/_/g, ' ')
  const source = evidenceSourceText(t, e)
  const first = typeof e.observed?.first_seen === 'string' ? e.observed.first_seen : ''
  if (first) {
    return t(
      'assets.attribution.evidence.lineSince',
      '{what} — seen in {technique} ({source}) since {date}',
      { what, technique, source, date: formatDay(first) }
    )
  }
  return t('assets.attribution.evidence.line', '{what} — seen in {technique} ({source})', {
    what,
    technique,
    source,
  })
}

/**
 * Where a piece of evidence came from, in words. A sensor is named by the
 * server (`source_label`: the organization's own sensor by name, or
 * "platform sensor"); a sensor id is never shown, so one the server could
 * not name reads "a removed sensor".
 */
export function evidenceSourceText(
  t: AttributionT,
  e: Pick<AttributionEvidence, 'source' | 'source_label'>
): string {
  if (e.source_label) return e.source_label
  if (e.source.startsWith('sensor:'))
    return t('assets.attribution.source.removedSensor', 'a removed sensor')
  if (e.source === 'certspotter') return t('assets.attribution.source.certSpotter', 'Cert Spotter')
  return e.source
}

/** The review hint of an address row (RFC-054 §4.3, §6.6); '' for an unknown one. */
export function reviewHintText(t: AttributionT, hint: string | undefined): string {
  if (hint === 'ip_needs_ip_entry')
    return t(
      'assets.attribution.hint.ipNeedsIpEntry',
      'Names never grant their addresses; this IP needs its own scope entry.'
    )
  return ''
}

export interface ReviewNetworkFacts {
  asn?: string
  org?: string
  shared?: boolean
  shared_provider?: string
  org_matches?: boolean
}

/** One line about the network an address sits in, for the review queue. */
export function reviewNetworkText(
  t: AttributionT,
  n: ReviewNetworkFacts | null | undefined
): string | null {
  if (!n) return null
  const who = [n.asn, n.org].filter(Boolean).join(' ')
  if (n.shared) {
    return t(
      'assets.attribution.network.shared',
      '{who}shared provider space{provider}; it cannot be added, because these addresses serve other organizations.',
      {
        who: who ? `${who}: ` : '',
        provider: n.shared_provider ? ` (${n.shared_provider})` : '',
      }
    )
  }
  if (!who) return null
  return n.org_matches
    ? t('assets.attribution.network.matches', '{who}, which matches your organization.', { who })
    : t('assets.attribution.network.plain', '{who}.', { who })
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

/**
 * Whether scans may reach the asset, from the scope side (RFC-054 §4.2):
 * covered by what, or not covered. `ok` is true when a scope entry, seed or
 * verified domain covers it; `canAdd` when adding a scope entry would help.
 */
export function scopeStandingText(
  t: AttributionT,
  a: Pick<AssetAttribution, 'scope_status' | 'covered_by'>
): { text: string; ok: boolean; canAdd: boolean } | null {
  const via = a.covered_by
  switch (a.scope_status) {
    case 'in_scope': {
      const pattern = via?.pattern
      if (!pattern)
        return { text: t('assets.attribution.scope.inScope', 'In scope.'), ok: true, canAdd: false }
      const verified = via?.proof === 'verified'
      const kind =
        via?.kind === 'seed'
          ? t('assets.attribution.scope.kindSeed', 'seed')
          : via?.kind === 'verified_domain'
            ? t('assets.attribution.scope.kindVerifiedDomain', 'verified domain')
            : t('assets.attribution.scope.kindEntry', 'scope entry')
      return {
        text: verified
          ? t(
              'assets.attribution.scope.throughVerified',
              'In scope through the {kind} {pattern} (verified).',
              { kind, pattern }
            )
          : t('assets.attribution.scope.through', 'In scope through the {kind} {pattern}.', {
              kind,
              pattern,
            }),
        ok: true,
        canAdd: false,
      }
    }
    case 'out_of_scope':
      return {
        text: t(
          'assets.attribution.scope.outOfScope',
          'Out of scope: no scope entry covers this name.'
        ),
        ok: false,
        canAdd: true,
      }
    case 'internal':
      return {
        text: t('assets.attribution.scope.internal', 'A private target: its scan zone decides.'),
        ok: true,
        canAdd: false,
      }
    case 'not_applicable':
      return {
        text: t(
          'assets.attribution.scope.notApplicable',
          'Scope entries do not apply to this kind of asset.'
        ),
        ok: true,
        canAdd: false,
      }
    default:
      return null
  }
}

/** What a scan does with this asset, in words. */
export function scanStanding(
  t: AttributionT,
  a: Pick<AssetAttribution, 'active_checks_allowed' | 'state' | 'active_checks_blocked_by'>
): string {
  if (a.active_checks_allowed)
    return t('assets.attribution.scan.reachable', 'Scans can reach this asset.')
  if (a.active_checks_blocked_by === 'unattributed')
    return t(
      'assets.attribution.scan.unattributed',
      'Scans skip this asset: no scope target, seed or verified domain covers it. Add it to Scoping › Scope.'
    )
  if (a.active_checks_blocked_by === 'out_of_scope')
    return t(
      'assets.attribution.scan.outOfScope',
      'Scans skip this asset: it is confirmed as yours, but no scope target, seed or verified domain covers it. Add it to Scoping › Scope to scan it.'
    )
  if (a.active_checks_blocked_by === 'wildcard_only')
    return t(
      'assets.attribution.scan.wildcardOnly',
      'Scans skip this asset: the name resolves only through a wildcard DNS record. Confirm it is yours before any active scan.'
    )
  if (a.active_checks_blocked_by === 'guardrailed')
    return t(
      'assets.attribution.scan.guardrailed',
      'Scans keep this asset passive: a platform guardrail holds it (a shared, CDN or cloud network, an unknown network, shared hosting, or a name outside your domains). Add it to Scoping › Scope if it is yours.'
    )
  if (a.active_checks_blocked_by === 'discovered')
    return t(
      'assets.attribution.scan.discovered',
      'Not in scope: passive only. Discovery found this asset and no scope entry covers it. Add it to scope to scan it.'
    )
  if (a.active_checks_blocked_by === 'rejected' && a.state !== 'rejected')
    return t(
      'assets.attribution.scan.underRejected',
      'Scans skip this asset: a name it sits under was marked not yours.'
    )
  if (a.state === 'needs_review' || a.state === 'candidate')
    return t(
      'assets.attribution.scan.untilConfirmed',
      'Scans skip this asset until its ownership is confirmed.'
    )
  return t(
    'assets.attribution.scan.passive',
    'Scans skip this asset; it is watched passively only.'
  )
}

/** The decisions to offer for a state (never the state it is already in). */
export function decisionsFor(state: AttributionState): AttributionDecision[] {
  const all: AttributionDecision[] = ['confirmed', 'rejected', 'dependency', 'monitor_only']
  return all.filter((d) => d !== state)
}
