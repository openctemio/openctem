/**
 * Organization-qualified links.
 *
 * Every link the platform sends out to a console page (notifications,
 * e-mails, chat and webhook deliveries, copy-link buttons) names the
 * organization it belongs to in the `org` query parameter (the organization
 * id; a slug is accepted too). `OrgLinkGate` reads it: when the signed-in
 * person is a member of that organization and it is not the selected one, it
 * switches through the same flow as the organization switcher (the API checks
 * the membership) before the page loads. The parameter grants nothing: a
 * person who is not a member gets the same "not found" as without it.
 */
import { getCookie } from '@/lib/cookies'
import { env } from '@/lib/env'

export const ORG_LINK_PARAM = 'org'

/** `href` (relative or absolute) with `org=<orgId>` set; unchanged without an org. */
export function withOrg(href: string, orgId: string | null | undefined): string {
  const org = orgId?.trim()
  if (!href || !org) return href
  const hashAt = href.indexOf('#')
  const hash = hashAt >= 0 ? href.slice(hashAt) : ''
  const beforeHash = hashAt >= 0 ? href.slice(0, hashAt) : href
  const queryAt = beforeHash.indexOf('?')
  const path = queryAt >= 0 ? beforeHash.slice(0, queryAt) : beforeHash
  const params = new URLSearchParams(queryAt >= 0 ? beforeHash.slice(queryAt + 1) : '')
  params.set(ORG_LINK_PARAM, org)
  return `${path}?${params.toString()}${hash}`
}

/** `search` ("?a=1&org=x") without the org parameter, as "" or "?a=1". */
export function withoutOrgParam(search: string): string {
  const params = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search)
  params.delete(ORG_LINK_PARAM)
  const rest = params.toString()
  return rest ? `?${rest}` : ''
}

/**
 * The absolute, shareable link to a console path in the selected
 * organization, for copy-link buttons.
 */
export function shareableLink(path: string): string {
  const origin = typeof window === 'undefined' ? '' : window.location.origin
  return withOrg(`${origin}${path}`, selectedOrgId())
}

/** The selected organization's id from the tenant cookie (as TenantProvider writes it). */
function selectedOrgId(): string | null {
  if (typeof window === 'undefined') return null
  const raw = getCookie(env.cookies.tenant)
  if (!raw) return null
  try {
    const id = (JSON.parse(raw) as { id?: unknown }).id
    return typeof id === 'string' ? id : null
  } catch {
    return null
  }
}
