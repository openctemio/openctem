/**
 * Pure helpers of the suggestion detail panel: the grouping
 * basis in words, the confidence band, the accept preview, the breaking
 * change hint of an upgrade and the claim conflicts of a 409.
 */

import { ApiClientError } from '@/lib/api/error-handler'
import { findingLocation, type FindingLocation } from '@/features/findings/lib/finding-location'
import type { FindingConflict, RemediationSuggestion, SuggestionMember } from '../api/types'

/** The grouping factors the generator records in fix_spec.basis. */
export const BASIS_FACTORS = [
  'same_package_target',
  'same_secret_value',
  'same_specific_solution_text',
  'same_rule',
  'same_finding_title',
] as const
export type BasisFactor = (typeof BASIS_FACTORS)[number]

/** The basis factors of a suggestion, known ones only, in a stable order. */
export function basisFactors(
  s: Pick<RemediationSuggestion, 'fix_spec' | 'key_kind'>
): BasisFactor[] {
  const raw = s.fix_spec?.basis
  const got = new Set(
    Array.isArray(raw) ? raw.filter((x): x is string => typeof x === 'string') : []
  )
  if (got.size === 0) {
    // Before the generator recorded factors: the key kind says the first one.
    if (s.key_kind === 'upgrade') got.add('same_package_target')
    else if (s.key_kind === 'rotate') got.add('same_secret_value')
    else if (s.key_kind === 'sol') got.add('same_specific_solution_text')
  }
  return BASIS_FACTORS.filter((f) => got.has(f))
}

/** The rule ids the generator recorded (at most 5). */
export function basisRules(s: Pick<RemediationSuggestion, 'fix_spec'>): string[] {
  const raw = s.fix_spec?.rule_ids
  return Array.isArray(raw) ? raw.filter((x): x is string => typeof x === 'string').slice(0, 5) : []
}

export type ConfidenceBand = 'exact' | 'high' | 'medium' | 'low'

/** 1 = an exact fix identity; then high (≥ 0.85), medium (≥ 0.7), low. */
export function confidenceBand(c: number): ConfidenceBand {
  if (c >= 1) return 'exact'
  if (c >= 0.85) return 'high'
  if (c >= 0.7) return 'medium'
  return 'low'
}

/** The leading number of a version ("v4.2.1" → 4), or undefined. */
export function majorVersion(v: string | undefined): number | undefined {
  const m = /^\s*v?(\d+)/i.exec(v ?? '')
  return m ? Number(m[1]) : undefined
}

/** An upgrade across a major version may break callers. */
export function crossesMajor(installed: string | undefined, target: string | undefined): boolean {
  const a = majorVersion(installed)
  const b = majorVersion(target)
  return a !== undefined && b !== undefined && b > a
}

/** The distinct installed versions of a page of members (for "current → target"). */
export function installedVersions(
  members: Pick<SuggestionMember, 'installed_version'>[]
): string[] {
  return [
    ...new Set(members.map((m) => m.installed_version?.trim()).filter((v): v is string => !!v)),
  ]
}

/** The earliest SLA due date of the kept members, as an ISO string. */
export function earliestDue(
  members: Pick<SuggestionMember, 'finding_id' | 'sla_deadline'>[],
  excluded: ReadonlySet<string> = new Set()
): string | undefined {
  let best: number | undefined
  let out: string | undefined
  for (const m of members) {
    if (excluded.has(m.finding_id) || !m.sla_deadline) continue
    const t = Date.parse(m.sla_deadline)
    if (!Number.isNaN(t) && (best === undefined || t < best)) {
      best = t
      out = m.sla_deadline
    }
  }
  return out
}

/** The distinct assets of the members, with their criticality, in first-seen order. */
export function memberAssets(
  members: SuggestionMember[]
): { id: string; name: string; criticality?: string; findings: number }[] {
  const out = new Map<
    string,
    { id: string; name: string; criticality?: string; findings: number }
  >()
  for (const m of members) {
    if (!m.asset_id) continue
    const cur = out.get(m.asset_id)
    if (cur) cur.findings++
    else
      out.set(m.asset_id, {
        id: m.asset_id,
        name: m.asset_name || '',
        criticality: m.asset_criticality || undefined,
        findings: 1,
      })
  }
  return [...out.values()]
}

export interface AcceptPreviewTask {
  index: number
  findings: number
  ownerUserId?: string
  ownerGroupId?: string
  assetOwner: boolean
}

/**
 * What accepting creates: one task per owner partition (findings left out
 * subtracted), or the findings added to the existing task of a join.
 */
export function acceptPreview(
  s: Pick<RemediationSuggestion, 'kind' | 'partitions' | 'member_count'>,
  excluded: ReadonlySet<string>
): { joins: boolean; tasks: AcceptPreviewTask[]; kept: number } {
  const kept = Math.max(s.member_count - excluded.size, 0)
  if (s.kind === 'join') return { joins: true, tasks: [], kept }
  const tasks = s.partitions
    .map((p, index) => ({
      index,
      findings: p.finding_ids.filter((id) => !excluded.has(id)).length,
      ownerUserId: p.owner_user_id,
      ownerGroupId: p.owner_group_id,
      assetOwner: p.owner_rule === 'asset_owner',
    }))
    .filter((p) => p.findings > 0)
  return { joins: false, tasks, kept }
}

/** The conflicts of a 409 FINDINGS_IN_OTHER_TASK answer, or null for any other error. */
export function claimConflicts(err: unknown): FindingConflict[] | null {
  if (!(err instanceof ApiClientError) || err.code !== 'FINDINGS_IN_OTHER_TASK') return null
  const raw = err.details?.conflicts
  if (!Array.isArray(raw)) return []
  return raw.filter(
    (c): c is FindingConflict =>
      !!c && typeof c === 'object' && typeof (c as FindingConflict).finding_id === 'string'
  )
}

/** A suggestion id from the URL: a UUID, else nothing (the value goes into an API path). */
export function suggestionParam(v: string | null | undefined): string | undefined {
  return v && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)
    ? v
    : undefined
}

/** Where a suggestion member is, the way the findings list shows it. */
export function memberLocation(m: SuggestionMember): FindingLocation {
  return findingLocation({
    asset: m.asset_name ? { name: m.asset_name } : null,
    file_path: m.file_path,
    start_line: m.start_line,
    first_detected_branch: m.first_detected_branch,
    network_port: m.network_port,
    network_transport: m.network_transport,
    metadata: m.location_targets?.length ? { affected_assets: m.location_targets } : null,
  })
}
