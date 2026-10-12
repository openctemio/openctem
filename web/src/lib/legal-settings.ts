import { env } from '@/lib/env'

/**
 * The operator's legal information, set in the admin console (System >
 * Legal) and served by the API at the public GET /api/v1/legal. It is read
 * on the server, per request (with a short cache), and handed to legalConfig /
 * securityTxt in the shape they read. When the API cannot be reached the
 * defaults apply (OpenCTEM contacts, no external links, legal pages off).
 */

type LegalRecord = Record<string, string | undefined>

interface LegalSettingsResponse {
  terms_url?: string
  privacy_url?: string
  pages_enabled?: boolean
  organization_name?: string
  service_name?: string
  contact_email?: string
  website_url?: string
  docs_url?: string
  address?: string
  jurisdiction?: string
  effective_date?: string
  security_contact?: string
  security_policy_url?: string
  security_txt_disabled?: boolean
}

export function toLegalRecord(s: LegalSettingsResponse): LegalRecord {
  return {
    LEGAL_TERMS_URL: s.terms_url,
    LEGAL_PRIVACY_URL: s.privacy_url,
    LEGAL_PAGES_ENABLED: s.pages_enabled ? 'true' : 'false',
    LEGAL_ORGANIZATION_NAME: s.organization_name,
    LEGAL_SERVICE_NAME: s.service_name,
    LEGAL_CONTACT_EMAIL: s.contact_email,
    LEGAL_WEBSITE_URL: s.website_url,
    LEGAL_DOCS_URL: s.docs_url,
    LEGAL_ADDRESS: s.address,
    LEGAL_JURISDICTION: s.jurisdiction,
    LEGAL_EFFECTIVE_DATE: s.effective_date,
    SECURITY_CONTACT: s.security_contact,
    SECURITY_POLICY_URL: s.security_policy_url,
    SECURITY_TXT_ENABLED: s.security_txt_disabled ? 'false' : 'true',
  }
}

/** Fetches the legal information; {} (the defaults) on any failure. */
export async function legalSettings(): Promise<LegalRecord> {
  try {
    const res = await fetch(`${env.api.url}/api/v1/legal`, {
      headers: { Accept: 'application/json' },
      next: { revalidate: 60 },
      signal: AbortSignal.timeout(3000),
    })
    if (!res.ok) return {}
    return toLegalRecord((await res.json()) as LegalSettingsResponse)
  } catch {
    return {}
  }
}
