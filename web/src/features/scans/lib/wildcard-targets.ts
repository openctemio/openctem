/**
 * A wildcard pattern (*.example.com) names a set of hosts, not a host. The
 * API refuses one for an active scanner (WILDCARD_TARGET) and hands a
 * discovery tool its root domain; these helpers let the Targets step offer
 * the two ways forward before the scan is saved.
 */

/**
 * Discovery (passive) tools that take a pattern as its root domain: the
 * passive tools of the API's stage catalog (stage.PassiveTools).
 */
export const DISCOVERY_TOOLS: ReadonlySet<string> = new Set(['subfinder', 'dnsx'])

/** The discovery tool the "Discover subdomains" choice switches to. */
export const SUBDOMAIN_DISCOVERY_TOOL = 'subfinder'

export function isWildcardTarget(target: string): boolean {
  return target.trim().startsWith('*.')
}

/** "*.Example.com" -> "example.com". */
export function wildcardRoot(target: string): string {
  return target.trim().replace(/^\*\./, '').toLowerCase()
}

/** The first wildcard pattern among targets, or null. */
export function firstWildcard(targets: readonly string[]): string | null {
  return targets.find(isWildcardTarget)?.trim() ?? null
}

/** Whether the chosen single scanner takes a pattern as its root domain. */
export function scannerTakesWildcard(scannerName: string | undefined): boolean {
  return DISCOVERY_TOOLS.has((scannerName ?? '').trim().toLowerCase())
}

/**
 * Known asset names that match the pattern: the root itself and every name
 * under it, deduplicated case-insensitively, in the order given.
 */
export function namesMatchingWildcard(names: readonly string[], pattern: string): string[] {
  const root = wildcardRoot(pattern)
  if (!root) return []
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of names) {
    const name = raw.trim()
    const lower = name.toLowerCase()
    if (!(lower === root || lower.endsWith('.' + root)) || seen.has(lower)) continue
    seen.add(lower)
    out.push(name)
  }
  return out
}

/**
 * The targets with `pattern` replaced by `replacement` (one or more names),
 * keeping order and dropping duplicates.
 */
export function replaceWildcard(
  targets: readonly string[],
  pattern: string,
  replacement: readonly string[]
): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const t of targets) {
    const items = t.trim() === pattern.trim() ? replacement : [t]
    for (const item of items) {
      const key = item.trim().toLowerCase()
      if (!key || seen.has(key)) continue
      seen.add(key)
      out.push(item.trim())
    }
  }
  return out
}
