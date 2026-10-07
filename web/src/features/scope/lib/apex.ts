import type { ScopeTargetType } from '../types'

const DOMAIN_TYPES: ReadonlySet<string> = new Set(['domain', 'subdomain', 'email_domain'])

/**
 * The apex T of a domain wildcard target ("*.T" / "**.T"), or null. A wildcard
 * covers subdomains only, never T itself (the API rule), so T must be its own
 * target to be scanned.
 */
export function wildcardApex(
  type: ScopeTargetType | string | undefined,
  pattern: string | undefined
): string | null {
  if (!type || !DOMAIN_TYPES.has(type) || !pattern) return null
  const m = /^\*\*?\.(.+)$/.exec(pattern.trim())
  const apex = m?.[1].trim().replace(/\.$/, '')
  return apex && !apex.startsWith('*') ? apex : null
}
