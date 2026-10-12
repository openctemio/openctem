/**
 * Turn a machine identifier ("sso.change_requested", "idp_create") into a
 * sentence-case label ("SSO change requested", "Identity provider create").
 *
 * The one place that knows how identifier words read in the console: an
 * acronym stays upper case, a product term uses the console's name for it
 * ("tenant" is an organization). Labels that need different wording than
 * the words give have their own map (audit actions: `getActionLabel`); this
 * is the fallback, so a new identifier never shows as raw text or as
 * Title-Cased Raw Words.
 */

const IDENTIFIER_WORDS: Record<string, string> = {
  ai: 'AI',
  api: 'API',
  ci: 'CI',
  cve: 'CVE',
  easm: 'EASM',
  idp: 'identity provider',
  ip: 'IP',
  jit: 'JIT',
  kev: 'KEV',
  mcp: 'MCP',
  mfa: 'two-step verification',
  oidc: 'OIDC',
  saml: 'SAML',
  sbom: 'SBOM',
  scim: 'SCIM',
  scm: 'SCM',
  siem: 'SIEM',
  sla: 'SLA',
  sso: 'SSO',
  tenant: 'organization',
  url: 'URL',
  vex: 'VEX',
}

/** One identifier word as the console writes it ("sso" -> "SSO"). */
export function identifierWord(word: string): string {
  return IDENTIFIER_WORDS[word.toLowerCase()] ?? word.toLowerCase()
}

/** "sso.change_requested" -> "SSO change requested". */
export function humanizeIdentifier(identifier: string): string {
  const words = identifier
    .split(/[._\-\s]+/)
    .filter(Boolean)
    .map(identifierWord)
    .join(' ')
  return words.charAt(0).toUpperCase() + words.slice(1)
}
