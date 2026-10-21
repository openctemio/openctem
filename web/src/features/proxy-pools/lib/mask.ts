/** The mask the API puts where a stored credential is. */
export const CREDENTIAL_MASK = '••••'

// scheme://userinfo@ where the userinfo is not already exactly the mask.
const USERINFO = /^([a-z][a-z0-9+.-]*:\/\/)(?!••••@)[^/@\s#]+@/i

/**
 * Defence in depth for text the API returns: credentials never reach the
 * screen, so any line that carries real userinfo is shown masked. The API
 * already masks; this only guards a regression there.
 */
export function maskPasteText(text: string): string {
  return text
    .split('\n')
    .map((line) => line.replace(USERINFO, `$1${CREDENTIAL_MASK}@`))
    .join('\n')
}

/** scheme://host:port of an endpoint, never userinfo. */
export function endpointUrl(e: { scheme: string; host: string; port: number }): string {
  const host = e.host.includes(':') && !e.host.startsWith('[') ? `[${e.host}]` : e.host
  return `${e.scheme}://${host}:${e.port}`
}

/** A 0 to 1 score as a whole percent. */
export function scorePercent(score: number): number {
  if (!Number.isFinite(score)) return 0
  return Math.round(Math.min(1, Math.max(0, score)) * 100)
}
