/**
 * Path exclusions (RFC-056 §5): a web rule, not an asset exclusion. A host
 * pattern, a path prefix and the methods it blocks (empty: every method).
 * Each has a testing mode an exclusion approver sets: blocked (default),
 * read_only (GET and HEAD) or allowed (in scope until a date, at most 90
 * days). Pure helpers shared by the dialog, the table and their tests.
 */

import type {
  ApiScopeExclusion,
  ExclusionTesting,
  PathExclusionFields,
} from '../api/scope-api.types'
import type { PillTone } from '@/features/shared'

export type PathExclusion = ApiScopeExclusion & PathExclusionFields

export const HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const
/** The suggested rule for a sensitive path: block what changes state. */
export const STATE_CHANGING_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']

/** The longest a testing window may last (the API refuses more). */
export const MAX_TESTING_DAYS = 90

export function isPathExclusion(x: { exclusion_type?: string }): boolean {
  return x.exclusion_type === 'path'
}

/** "*.acme.io/admin" for display; the API stores host + prefix together. */
export function pathRuleLabel(x: PathExclusion): string {
  const host = x.host_pattern || '*'
  const prefix = x.path_prefix || ''
  return x.path_prefix ? `${host}${prefix.startsWith('/') ? '' : '/'}${prefix}` : x.pattern || host
}

/** Which methods it blocks, in words. */
export function methodsText(methods: string[] | undefined): string {
  if (!methods || methods.length === 0) return 'every method'
  return methods.join(', ')
}

export const TESTING_LABEL: Record<ExclusionTesting, string> = {
  blocked: 'Blocked',
  read_only: 'Read-only',
  allowed: 'Allowed',
}

export const TESTING_TONE: Record<ExclusionTesting, PillTone> = {
  blocked: 'muted',
  read_only: 'info',
  allowed: 'warning',
}

export const TESTING_HINT: Record<ExclusionTesting, string> = {
  blocked: 'Nothing is sent to these paths.',
  read_only: 'Only GET and HEAD requests reach these paths, so read-only checks run.',
  allowed: 'These paths are treated as in scope until the end date, then blocked again.',
}

/** The testing mode in force now (the server's `testing_effective` first). */
export function effectiveTesting(x: PathExclusionFields): ExclusionTesting {
  return x.testing_effective ?? x.testing ?? 'blocked'
}

/** What a change of testing mode does, in one sentence (review step). */
export function testingImpact(
  from: ExclusionTesting,
  to: ExclusionTesting,
  rule: string,
  methods: string[] | undefined
): string {
  if (from === to) return 'Nothing changes.'
  if (to === 'blocked')
    return `Scans stop sending requests to ${rule} (${methodsText(methods)} blocked again).`
  if (to === 'read_only')
    return `Endpoints under ${rule} become testable with GET and HEAD; ${methodsText(methods)} stay blocked otherwise.`
  return `Endpoints under ${rule} are tested like any in-scope path until the end date. Hosts outside your scope stay refused.`
}

/** Validate a testing change: allowed needs an end date; at most 90 days. */
export function testingProblem(to: ExclusionTesting, days: number | null): string | null {
  if (days !== null && (!Number.isInteger(days) || days < 1 || days > MAX_TESTING_DAYS))
    return `The end must be 1 to ${MAX_TESTING_DAYS} days from now.`
  if (to === 'allowed' && days === null)
    return 'Allowed testing needs an end date (at most 90 days).'
  return null
}

/**
 * A path prefix the API accepts: starts with "/", no dot segments, no
 * encoded slashes or NUL, "*" only as a whole segment. The server checks
 * again; this only explains before the click.
 */
export function pathPrefixProblem(prefix: string): string | null {
  const p = prefix.trim()
  if (!p) return 'Enter the path prefix, for example /admin.'
  if (!p.startsWith('/')) return 'The path starts with /.'
  if (/%2f|%5c|%00/i.test(p)) return 'Encoded slashes are not allowed in the path.'
  const segs = p.split('/').slice(1)
  if (segs.some((s) => s === '.' || s === '..')) return 'Dot segments (. or ..) are not allowed.'
  if (segs.some((s) => s.includes('*') && s !== '*')) return '* may stand only for a whole segment.'
  return null
}
