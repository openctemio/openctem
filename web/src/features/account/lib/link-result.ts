/**
 * Where the OAuth callback sends the browser after linking a provider to the
 * signed-in account, and how Account > Security reads it back. Only a known
 * provider and an API error code travel in the URL; the page shows its own
 * text for the code (errors.auth.<CODE>), never free text from the URL.
 */

export const LINK_PROVIDERS = ['google', 'github', 'microsoft'] as const
export type LinkProvider = (typeof LINK_PROVIDERS)[number]

export const ACCOUNT_SECURITY_PATH = '/account/security'

/** `/account/security?linked=<provider>` or `?link_error=<CODE>&provider=<provider>`. */
export function linkResultHref(provider: LinkProvider, errorCode?: string): string {
  const params = new URLSearchParams(
    errorCode ? { link_error: errorCode, provider } : { linked: provider }
  )
  return `${ACCOUNT_SECURITY_PATH}?${params.toString()}`
}

export type LinkResult =
  | { kind: 'linked'; provider: LinkProvider }
  | { kind: 'error'; provider?: LinkProvider; code: string }
  | null

function asProvider(v: string | null): LinkProvider | undefined {
  return v && (LINK_PROVIDERS as readonly string[]).includes(v) ? (v as LinkProvider) : undefined
}

/** Reads the link result from the page's query, or null when there is none. */
export function readLinkResult(params: URLSearchParams): LinkResult {
  const linked = asProvider(params.get('linked'))
  if (linked) return { kind: 'linked', provider: linked }
  const code = params.get('link_error')
  if (code && /^[A-Z_]{1,64}$/.test(code)) {
    return { kind: 'error', provider: asProvider(params.get('provider')), code }
  }
  return null
}
