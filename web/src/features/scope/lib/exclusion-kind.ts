/**
 * Why something is out of scope (research/320, RFC-054 §20): the labels of
 * the three exclusion kinds, shared by the Scoping exclusion dialog, the
 * exclusions table and the inventory's Mark out of scope dialog.
 */

import type { ScopeExclusionKind } from '../api/scope-api.types'
import type { Translate } from './scope-codes'

export const SCOPE_EXCLUSION_KINDS: ScopeExclusionKind[] = ['not_ours', 'retired', 'do_not_scan']

export function scopeExclusionKindLabel(t: Translate, k: ScopeExclusionKind | string | undefined) {
  switch (k) {
    case 'not_ours':
      return t('scope.exclusion.kind.notOurs', 'Not ours')
    case 'retired':
      return t('scope.exclusion.kind.retired', 'Retired')
    default:
      return t('scope.exclusion.kind.doNotScan', 'Do not scan')
  }
}

/** Entry types whose exclusion names hosts (and so may say "not ours"). */
const HOST_ENTRY_TYPES = new Set([
  'domain',
  'subdomain',
  'wildcard',
  'ip_address',
  'cidr',
  'ip_range',
  'url',
  'repository',
])

/**
 * The exclusion pattern "No longer ours" proposes for a scope entry: for a
 * domain entry the root and every name under it (`*.root`), otherwise the
 * entry's own pattern. Undefined when the entry names no host.
 */
export function noLongerOursPattern(e: {
  target_type?: string
  pattern?: string
}): string | undefined {
  const pattern = (e.pattern ?? '').trim()
  if (!pattern || !HOST_ENTRY_TYPES.has(e.target_type ?? '')) return undefined
  if (e.target_type === 'domain' || e.target_type === 'subdomain' || e.target_type === 'wildcard') {
    return `*.${pattern.replace(/^\*+\.?/, '')}`
  }
  return pattern
}
