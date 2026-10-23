/**
 * The CTIS members a tenant mapping may set, as the API accepts them. The API
 * refuses every other target; these lists only drive the editor's dropdowns.
 */

import type { RuleKind } from '../types/import-mapping.types'

export const FINDING_TARGETS = [
  'title',
  'severity',
  'description',
  'message',
  'rule_id',
  'rule_name',
  'category',
  'confidence',
  'impact',
  'likelihood',
  'asset_value',
  'asset_type',
  'evidence',
  'references',
  'tags',
  'location.path',
  'location.start_line',
  'location.end_line',
  'location.snippet',
  'network.host',
  'network.port',
  'network.protocol',
  'vulnerability.cve_id',
  'vulnerability.cwe_ids',
  'vulnerability.cvss_score',
  'vulnerability.cvss_vector',
  'vulnerability.package',
  'vulnerability.affected_version',
  'vulnerability.fixed_version',
  'vulnerability.purl',
  'vulnerability.ecosystem',
  'misconfiguration.policy_id',
  'misconfiguration.resource_type',
  'misconfiguration.resource_name',
  'remediation.recommendation',
  'type',
] as const

export const ASSET_TARGETS = ['type', 'value', 'name', 'description', 'tags'] as const

/** Finding members that may identify a finding. */
export const IDENTITY_ELIGIBLE = [
  'title',
  'rule_id',
  'asset_value',
  'location.path',
  'location.start_line',
  'vulnerability.cve_id',
  'vulnerability.package',
  'vulnerability.purl',
  'network.host',
  'network.port',
  'network.protocol',
  'misconfiguration.policy_id',
  'misconfiguration.resource_type',
  'misconfiguration.resource_name',
] as const

/** Members every rule of a kind must set. */
export const REQUIRED_TARGETS: Record<RuleKind, string[]> = {
  finding: ['title', 'severity'],
  asset: ['type', 'value'],
  dependency: ['name'],
}

export const MAX_IDENTITY = 8

export function targetsFor(kind: RuleKind): readonly string[] {
  if (kind === 'finding') return FINDING_TARGETS
  if (kind === 'asset') return ASSET_TARGETS
  return []
}

export function isIdentityEligible(target: string): boolean {
  return (IDENTITY_ELIGIBLE as readonly string[]).includes(target)
}

/** A mapping name: a slug used in `format=mapping:<name>`. */
export const MAPPING_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/

/** The largest sample the preview accepts. */
export const MAX_SAMPLE_BYTES = 5 * 1024 * 1024
