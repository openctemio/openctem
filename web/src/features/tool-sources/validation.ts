export const MAX_KEY_LENGTH = 1024

/** The shortest secret part of a key (the API refuses shorter ones). */
export const MIN_SECRET_LENGTH = 8

export type KeyValueError = 'empty' | 'whitespace' | 'tooLong' | 'pairFormat' | 'tooShort'

/**
 * Client-side check of a key value; the API validates again, including the
 * host or endpoint URL a pair may name. A pair's secret is the part after its
 * last colon (an endpoint URL holds a colon of its own). Returns null when
 * acceptable.
 */
export function validateKeyValue(value: string, format: 'key' | 'pair'): KeyValueError | null {
  if (value.length === 0) return 'empty'
  if (/\s/.test(value)) return 'whitespace'
  if (value.length > MAX_KEY_LENGTH) return 'tooLong'
  let secret = value
  if (format === 'pair') {
    const i = value.lastIndexOf(':')
    if (i <= 0 || i === value.length - 1) return 'pairFormat'
    secret = value.slice(i + 1)
  }
  if (secret.length < MIN_SECRET_LENGTH) return 'tooShort'
  return null
}
