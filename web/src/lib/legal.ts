/**
 * The operator's legal documents and security contact, set in the admin
 * console (System > Legal) and read on the server at request time
 * (legal-settings.ts fetches them; these functions take them as a record).
 *
 * - LEGAL_PAGES_ENABLED serves the built-in templates: /terms,
 *   /acceptable-use, /privacy, /dpa and /subprocessors, filled from the LEGAL_*
 *   values; the contacts default to the OpenCTEM ones (info@openctem.io,
 *   security@openctem.io, https://openctem.io, https://docs.openctem.io). The
 *   company legal name, address and governing law have no default: until they
 *   are set they show as clearly marked placeholders. The templates are a
 *   starting point reviewed with counsel, not legal advice. Off by default:
 *   the pages answer 404.
 * - LEGAL_TERMS_URL / LEGAL_PRIVACY_URL point at documents hosted elsewhere
 *   and win over the templates in the sign-in and sign-up notices.
 * - /.well-known/security.txt (RFC 9116) names SECURITY_CONTACT (an email
 *   address or an https URL), security@openctem.io by default;
 *   SECURITY_POLICY_URL sets the Policy line, which defaults to the OpenCTEM
 *   disclosure policy while the contact is the default one.
 *   SECURITY_TXT_ENABLED=false turns the file off (404).
 */

import { DEFAULT_BRAND } from '@/lib/brand'

type Env = Record<string, string | undefined>

export const DEFAULT_CONTACTS = {
  general: DEFAULT_BRAND.supportEmail,
  security: 'security@openctem.io',
  website: DEFAULT_BRAND.websiteUrl,
  docs: DEFAULT_BRAND.docsUrl,
  securityPolicy: `${DEFAULT_BRAND.docsUrl}/security/vulnerability-disclosure/`,
} as const

export interface LegalValues {
  /** The company's legal name (pending from the owner: placeholder). */
  organization: string
  /** The product or service name. */
  service: string
  contactEmail: string
  securityEmail: string
  website: string
  docsUrl: string
  address: string
  jurisdiction: string
  effectiveDate: string
}

export type LegalDoc = 'terms' | 'acceptable-use' | 'privacy' | 'dpa' | 'subprocessors'

export const LEGAL_DOCS: readonly { doc: LegalDoc; path: string; title: string }[] = [
  { doc: 'terms', path: '/terms', title: 'Terms of Service' },
  { doc: 'acceptable-use', path: '/acceptable-use', title: 'Acceptable Use Policy' },
  { doc: 'privacy', path: '/privacy', title: 'Privacy Policy' },
  { doc: 'dpa', path: '/dpa', title: 'Data Processing Addendum' },
  { doc: 'subprocessors', path: '/subprocessors', title: 'Subprocessors' },
]

export interface LegalConfig {
  /** The built-in templates are served. */
  templatesEnabled: boolean
  /** Where the sign-in and sign-up notices link; '' when there is none. */
  termsUrl: string
  privacyUrl: string
  values: LegalValues
}

/** Placeholders for what only the owner can provide; visible on the page. */
export const PENDING = {
  organization: '[Company legal name: to be confirmed]',
  address: '[Registered address: to be confirmed]',
  jurisdiction: '[Governing law and courts: to be confirmed]',
  effectiveDate: '[Effective date: to be confirmed]',
} as const

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

const EMAIL = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/

function email(v: string | undefined, fallback: string): string {
  const c = clean(v)
  return EMAIL.test(c) ? c : fallback
}

function httpsUrl(v: string | undefined, fallback: string): string {
  const c = clean(v)
  try {
    return c && new URL(c).protocol === 'https:' ? c : fallback
  } catch {
    return fallback
  }
}

export function legalConfig(env: Env = {}): LegalConfig {
  const templatesEnabled = clean(env.LEGAL_PAGES_ENABLED).toLowerCase() === 'true'
  const terms = safeUrl(clean(env.LEGAL_TERMS_URL))
  const privacy = safeUrl(clean(env.LEGAL_PRIVACY_URL))
  return {
    templatesEnabled,
    termsUrl: terms || (templatesEnabled ? '/terms' : ''),
    privacyUrl: privacy || (templatesEnabled ? '/privacy' : ''),
    values: {
      organization: clean(env.LEGAL_ORGANIZATION_NAME) || PENDING.organization,
      service: clean(env.LEGAL_SERVICE_NAME) || DEFAULT_BRAND.name,
      contactEmail: email(env.LEGAL_CONTACT_EMAIL, DEFAULT_CONTACTS.general),
      securityEmail: email(env.SECURITY_CONTACT, DEFAULT_CONTACTS.security),
      website: httpsUrl(env.LEGAL_WEBSITE_URL, DEFAULT_CONTACTS.website),
      docsUrl: httpsUrl(env.LEGAL_DOCS_URL, DEFAULT_CONTACTS.docs),
      address: clean(env.LEGAL_ADDRESS) || PENDING.address,
      jurisdiction: clean(env.LEGAL_JURISDICTION) || PENDING.jurisdiction,
      effectiveDate: clean(env.LEGAL_EFFECTIVE_DATE) || PENDING.effectiveDate,
    },
  }
}

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
 * The body of /.well-known/security.txt (RFC 9116), or null when it is turned
 * off or the configured contact is not valid. The contact defaults to
 * security@openctem.io, with the OpenCTEM disclosure policy as Policy.
 * Expires is one year from `now` (the file is generated per request, so it
 * never goes stale).
 */
export function securityTxt(env: Env = {}, now: Date = new Date()): string | null {
  if (clean(env.SECURITY_TXT_ENABLED).toLowerCase() === 'false') return null
  const configured = clean(env.SECURITY_CONTACT)
  const contact = securityContactUri(configured || DEFAULT_CONTACTS.security)
  if (!contact) return null
  const expires = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000)
  const lines = [`Contact: ${contact}`, `Expires: ${expires.toISOString()}`]
  // Our own policy goes with our own contact only: an operator who sets their
  // own contact sets their own policy (or none).
  const policy =
    clean(env.SECURITY_POLICY_URL) || (configured ? '' : DEFAULT_CONTACTS.securityPolicy)
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
