/**
 * The one place a capability id ("enumerate.subdomains", "probe.http") becomes
 * words in the reader's language. Every surface that names a capability
 * (discovery stages, workflow nodes, coverage, capability badges, server
 * messages) calls this, so a capability reads the same everywhere and never as
 * its raw id. The catalog is `assetCoverage.capability.<id>`; an id it does
 * not have reads as the caller's name for it, else as the id in words.
 */

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/** "enumerate.web_paths" -> "Enumerate web paths" (the last resort). */
export function capabilityIdInWords(id: string): string {
  const words = id.replace(/[._]+/g, ' ').trim()
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : id
}

export function capabilityLabel(id: string, t: Translate, fallback?: string): string {
  if (!id) return fallback ?? ''
  return t(`assetCoverage.capability.${id}`, fallback || capabilityIdInWords(id))
}
