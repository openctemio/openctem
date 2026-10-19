/**
 * Autocomplete for the query box: the word under the caret and what may
 * complete it (field paths, keywords, and the enum values of the field the
 * clause names). Suggestions come from GET /api/v1/query/schema, which lists
 * only the fields the caller may use.
 */

import type { QuerySchemaField } from '../api/use-task-query'

export const QUERY_KEYWORDS = ['where', 'and', 'or', 'not', 'in', 'is', 'empty', 'between'] as const

export interface Token {
  word: string
  start: number
  end: number
}

const WORD = /[A-Za-z0-9_.-]/

/** The word that ends at the caret (letters, digits, _ . -). */
export function tokenAt(text: string, caret: number): Token {
  let start = caret
  while (start > 0 && WORD.test(text[start - 1])) start--
  return { word: text.slice(start, caret), start, end: caret }
}

/** The last field path named before the token, for enum suggestions. */
export function fieldBefore(
  text: string,
  start: number,
  fields: QuerySchemaField[]
): QuerySchemaField | null {
  const words = text.slice(0, start).match(/[A-Za-z0-9_.]+/g) ?? []
  for (let i = words.length - 1; i >= 0 && i >= words.length - 4; i--) {
    const f = fields.find((x) => x.path === words[i])
    if (f) return f
  }
  return null
}

/** Up to limit completions for the word at the caret. */
export function suggest(
  text: string,
  caret: number,
  fields: QuerySchemaField[],
  limit = 8
): string[] {
  const tok = tokenAt(text, caret)
  const w = tok.word.toLowerCase()
  if (w.length === 0) return []
  const field = fieldBefore(text, tok.start, fields)
  const pool: string[] = []
  if (field?.enum) pool.push(...field.enum)
  pool.push(...fields.map((f) => f.path), ...QUERY_KEYWORDS)
  const seen = new Set<string>()
  const out: string[] = []
  for (const p of pool) {
    const k = p.toLowerCase()
    if (k === w || seen.has(k) || !k.startsWith(w)) continue
    seen.add(k)
    out.push(p)
    if (out.length >= limit) break
  }
  return out
}

/** The text with the word at the caret replaced by value, and the new caret. */
export function applySuggestion(
  text: string,
  caret: number,
  value: string
): { text: string; caret: number } {
  const tok = tokenAt(text, caret)
  const next = text.slice(0, tok.start) + value + text.slice(tok.end)
  return { text: next, caret: tok.start + value.length }
}
