export const MAX_KEY_LENGTH = 1024

export type KeyValueError = 'empty' | 'whitespace' | 'tooLong' | 'pairFormat'

/** Client-side check of a key value; the API validates again. Returns null when acceptable. */
export function validateKeyValue(value: string, format: 'key' | 'pair'): KeyValueError | null {
  if (value.length === 0) return 'empty'
  if (/\s/.test(value)) return 'whitespace'
  if (value.length > MAX_KEY_LENGTH) return 'tooLong'
  if (format === 'pair') {
    const parts = value.split(':')
    if (parts.length !== 2 || parts[0] === '' || parts[1] === '') return 'pairFormat'
  }
  return null
}
