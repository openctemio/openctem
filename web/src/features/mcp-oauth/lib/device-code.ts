/**
 * The code a terminal shows when it signs in with the device authorization
 * grant (api docs/rfcs/RFC-062 §6a): 8 characters of a base-20 set of
 * consonants, shown XXXX-XXXX.
 */

const ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ'
export const USER_CODE_LENGTH = 8

/**
 * Normalises what the person typed the way the API does: case-folded,
 * dashes and spaces dropped. Null when it cannot be a code (the API would
 * answer the same uniform 404 anyway).
 */
export function normalizeUserCode(input: string): string | null {
  let out = ''
  for (const ch of input.toUpperCase()) {
    if (ch === '-' || ch === ' ' || ch === '\t') continue
    if (!ALPHABET.includes(ch)) return null
    out += ch
  }
  return out.length === USER_CODE_LENGTH ? out : null
}

/**
 * Formats input while it is typed: upper case, characters outside the set
 * dropped, a dash after the fourth, at most 8 characters.
 */
export function formatUserCodeInput(input: string): string {
  const chars = [...input.toUpperCase()]
    .filter((c) => ALPHABET.includes(c))
    .slice(0, USER_CODE_LENGTH)
  const s = chars.join('')
  return s.length > 4 ? `${s.slice(0, 4)}-${s.slice(4)}` : s
}
