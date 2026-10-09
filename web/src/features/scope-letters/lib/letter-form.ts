/**
 * Checks of the letter upload form before it is sent (the server checks
 * everything again: type by content, size, validity of at most two years).
 */

export const LETTER_MAX_BYTES = 10 * 1024 * 1024
export const LETTER_TYPES = ['application/pdf', 'image/png', 'image/jpeg']
export const LETTER_MAX_DAYS = 731

export type LetterFormProblem =
  | 'file_missing'
  | 'file_type'
  | 'file_size'
  | 'title_missing'
  | 'dates_missing'
  | 'dates_order'
  | 'dates_too_long'

export interface LetterFormValues {
  file: { type: string; size: number } | null
  title: string
  validFrom: string
  validUntil: string
}

const DAY_MS = 24 * 60 * 60 * 1000

/** The first problem of the form, or null when it can be sent. */
export function letterFormProblem(v: LetterFormValues): LetterFormProblem | null {
  if (!v.file) return 'file_missing'
  if (!LETTER_TYPES.includes(v.file.type)) return 'file_type'
  if (v.file.size <= 0 || v.file.size > LETTER_MAX_BYTES) return 'file_size'
  if (!v.title.trim()) return 'title_missing'
  const from = Date.parse(`${v.validFrom}T00:00:00Z`)
  const until = Date.parse(`${v.validUntil}T00:00:00Z`)
  if (Number.isNaN(from) || Number.isNaN(until)) return 'dates_missing'
  if (until <= from) return 'dates_order'
  if (until - from > LETTER_MAX_DAYS * DAY_MS) return 'dates_too_long'
  return null
}

export const LETTER_PROBLEM_TEXT: Record<LetterFormProblem, string> = {
  file_missing: 'Choose the signed letter (PDF, PNG or JPEG).',
  file_type: 'The letter must be a PDF, PNG or JPEG file.',
  file_size: 'The letter must be at most 10 MB.',
  title_missing: 'Give the letter a title.',
  dates_missing: 'Enter the dates the letter is valid from and until.',
  dates_order: 'The letter must end after it starts.',
  dates_too_long: 'A letter is valid for at most two years.',
}

/** Days until a letter ends (negative: ended), from now. */
export function daysLeft(validUntil: string, now: number = Date.now()): number {
  return Math.ceil((Date.parse(validUntil) - now) / DAY_MS)
}
