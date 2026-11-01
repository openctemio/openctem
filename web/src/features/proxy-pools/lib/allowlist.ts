/**
 * Allowlist snippets for the scanner addresses: the same prefix list in a
 * few common text formats a WAF, an edge or a web server accepts. Pure, so
 * the card and its tests share it.
 */

export type AllowlistFormat = 'lines' | 'comma' | 'allow' | 'require' | 'json'

export const ALLOWLIST_FORMATS: AllowlistFormat[] = ['lines', 'comma', 'allow', 'require', 'json']

/** The prefixes in one format ("" for none). */
export function allowlistSnippet(cidrs: string[], format: AllowlistFormat): string {
  if (cidrs.length === 0) return ''
  switch (format) {
    case 'lines':
      return cidrs.join('\n')
    case 'comma':
      return cidrs.join(', ')
    case 'allow':
      return cidrs.map((c) => `allow ${c};`).join('\n')
    case 'require':
      return `Require ip ${cidrs.join(' ')}`
    case 'json':
      return JSON.stringify(cidrs, null, 2)
  }
}
