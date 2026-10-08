/**
 * The operator's legal documents and security contact, read on the server at
 * request time (a published image is configured by its environment, not at
 * build time).
 *
 * - LEGAL_PAGES_ENABLED=true serves the built-in templates at /terms and
 *   /privacy, filled from LEGAL_ORGANIZATION_NAME, LEGAL_CONTACT_EMAIL,
 *   LEGAL_ADDRESS, LEGAL_JURISDICTION and LEGAL_EFFECTIVE_DATE. A value that
 *   is not set shows as a bracketed placeholder, so an unfinished template is
 *   visible. The templates are a starting point for the operator and their
 *   counsel, not legal advice. Off by default: the pages answer 404.
 * - LEGAL_TERMS_URL / LEGAL_PRIVACY_URL (or the older NEXT_PUBLIC_TERMS_URL /
 *   NEXT_PUBLIC_PRIVACY_URL) point at documents hosted elsewhere and win over
 *   the templates.
 * - SECURITY_CONTACT (an email address or an https URL) publishes
 *   /.well-known/security.txt (RFC 9116); SECURITY_POLICY_URL adds a Policy
 *   line. Without a contact the file answers 404.
 */

type Env = Record<string, string | undefined>

export interface LegalValues {
  organization: string
  contactEmail: string
  address: string
  jurisdiction: string
  effectiveDate: string
}

export interface LegalConfig {
  /** The built-in /terms and /privacy templates are served. */
  templatesEnabled: boolean
  /** Where the sign-in and sign-up notices link; '' when there is none. */
  termsUrl: string
  privacyUrl: string
  values: LegalValues
}

const PLACEHOLDER: LegalValues = {
  organization: '[Organization name]',
  contactEmail: '[Contact email]',
  address: '[Postal address]',
  jurisdiction: '[Governing law]',
  effectiveDate: '[Effective date]',
}

function clean(v: string | undefined): string {
  return (v ?? '').trim()
}

/** Only http(s) URLs or site-relative paths are linked. */
function safeUrl(v: string): string {
  if (v.startsWith('/') && !v.startsWith('//')) return v
  try {
    const u = new URL(v)
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : ''
  } catch {
    return ''
  }
}

export function legalConfig(env: Env = process.env): LegalConfig {
  const templatesEnabled = clean(env.LEGAL_PAGES_ENABLED).toLowerCase() === 'true'
  const external = (a: string | undefined, b: string | undefined) => safeUrl(clean(a) || clean(b))
  const terms = external(env.LEGAL_TERMS_URL, env.NEXT_PUBLIC_TERMS_URL)
  const privacy = external(env.LEGAL_PRIVACY_URL, env.NEXT_PUBLIC_PRIVACY_URL)
  return {
    templatesEnabled,
    termsUrl: terms || (templatesEnabled ? '/terms' : ''),
    privacyUrl: privacy || (templatesEnabled ? '/privacy' : ''),
    values: {
      organization: clean(env.LEGAL_ORGANIZATION_NAME) || PLACEHOLDER.organization,
      contactEmail: clean(env.LEGAL_CONTACT_EMAIL) || PLACEHOLDER.contactEmail,
      address: clean(env.LEGAL_ADDRESS) || PLACEHOLDER.address,
      jurisdiction: clean(env.LEGAL_JURISDICTION) || PLACEHOLDER.jurisdiction,
      effectiveDate: clean(env.LEGAL_EFFECTIVE_DATE) || PLACEHOLDER.effectiveDate,
    },
  }
}

const EMAIL = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/

/** "mailto:…" for an address, the URL for an https URL, '' for anything else. */
export function securityContactUri(contact: string): string {
  const c = contact.trim()
  if (c.startsWith('mailto:')) return EMAIL.test(c.slice(7)) ? c : ''
  if (EMAIL.test(c)) return `mailto:${c}`
  try {
    const u = new URL(c)
    return u.protocol === 'https:' ? u.toString() : ''
  } catch {
    return ''
  }
}

/**
 * The body of /.well-known/security.txt (RFC 9116), or null when no valid
 * contact is configured. Expires is one year from `now` (the file is
 * generated per request, so it never goes stale).
 */
export function securityTxt(env: Env = process.env, now: Date = new Date()): string | null {
  const contact = securityContactUri(clean(env.SECURITY_CONTACT))
  if (!contact) return null
  const expires = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000)
  const lines = [`Contact: ${contact}`, `Expires: ${expires.toISOString()}`]
  const policy = clean(env.SECURITY_POLICY_URL)
  if (policy) {
    try {
      const u = new URL(policy)
      if (u.protocol === 'https:') lines.push(`Policy: ${u.toString()}`)
    } catch {
      // ignored: an invalid policy URL is left out
    }
  }
  lines.push('Preferred-Languages: en, vi')
  return lines.join('\n') + '\n'
}
