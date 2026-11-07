/**
 * Completion for the search box: what the caret is in (a field name, the
 * value of a condition, nothing) and what may complete it. Field names and
 * enum values come from GET /api/v1/query/schema (only the fields the caller
 * may use); other values come from GET /api/v1/query/values. The server
 * parser is the authority on validity: this only reads the text near the
 * caret.
 */

import type { QuerySchemaField } from '../api/query-api'

export const SHORT_KEYWORDS = ['AND', 'OR', 'NOT'] as const

/** Ages offered for time fields ("last_seen_at<7d"). */
export const AGE_VALUES = ['1d', '7d', '30d', '90d'] as const

export type CompletionKind = 'field' | 'operator' | 'value' | 'keyword' | 'recent'

export interface Completion {
  kind: CompletionKind
  label: string
  insert: string
  count?: number
}

export interface CaretContext {
  kind: 'field' | 'value' | 'none'
  /** The range the completion replaces: [start, end). */
  start: number
  end: number
  /** The text being completed (a field prefix or a value prefix). */
  prefix: string
  /** The field path written before the operator (value context). */
  path?: string
  op?: string
  /** The text without the clause at the caret: the filter values are counted under. */
  rest: string
}

const CONDITION = /^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*(>=|<=|!=|=|:|>|<|~)([\s\S]*)$/
const NAME = /^[A-Za-z_][\w.]*$/

/** Where the caret is: in a field name, in a value, or neither. */
export function contextAt(text: string, caret: number): CaretContext {
  const before = text.slice(0, caret)
  const none: CaretContext = { kind: 'none', start: caret, end: caret, prefix: '', rest: text }
  if ((before.match(/"/g)?.length ?? 0) % 2 === 1) return none // inside a quoted value
  let s = caret
  while (s > 0 && !/[\s(]/.test(text[s - 1])) s--
  let e = caret
  while (e < text.length && !/[\s)]/.test(text[e])) e++
  let clause = text.slice(s, caret)
  let start = s
  if (clause.startsWith('-')) {
    clause = clause.slice(1)
    start++
  }
  const rest = (text.slice(0, s) + text.slice(e)).replace(/\s+/g, ' ').trim()
  const m = CONDITION.exec(clause)
  if (m) {
    const values = m[3]
    const last = values.lastIndexOf(',')
    const prefix = values.slice(last + 1)
    return {
      kind: 'value',
      start: caret - prefix.length,
      end: caret,
      prefix,
      path: m[1].toLowerCase(),
      op: m[2],
      rest,
    }
  }
  if (clause === '' || NAME.test(clause)) {
    return { kind: 'field', start, end: caret, prefix: clause, rest }
  }
  return none
}

/** Operators of a field in the short form, in the order people use them. */
export function shortOperators(f: QuerySchemaField): string[] {
  const ops = new Set(f.operators)
  const out: string[] = []
  if (ops.has('=') || ops.has('in')) out.push('=')
  if (ops.has('!=') || ops.has('not in')) out.push('!=')
  for (const o of ['>=', '<=', '>', '<', '~']) if (ops.has(o)) out.push(o)
  if (f.type === 'enum' && f.enum && f.enum.length > 2 && ORDERED.has(f.path)) out.push('>=', '<=')
  return Array.from(new Set(out))
}

// Ordered values: "at least" reads naturally on these.
const ORDERED = new Set(['severity', 'priority_class', 'asset.criticality'])

/** Field names, operators and keywords for the field at the caret. */
export function fieldCompletions(
  ctx: CaretContext,
  fields: QuerySchemaField[],
  limit = 10
): Completion[] {
  const p = ctx.prefix.toLowerCase()
  const exact = fields.find((f) => f.path === p)
  if (exact) {
    return shortOperators(exact).map((op) => ({
      kind: 'operator',
      label: exact.path + op,
      insert: exact.path + op,
    }))
  }
  const out: Completion[] = []
  if (p) {
    for (const k of SHORT_KEYWORDS) {
      if (k.toLowerCase().startsWith(p) && k.toLowerCase() !== p)
        out.push({ kind: 'keyword', label: k, insert: k + ' ' })
    }
  }
  const starts = fields.filter((f) => f.path.startsWith(p))
  const contains = p ? fields.filter((f) => !f.path.startsWith(p) && f.path.includes(p)) : []
  for (const f of [...starts, ...contains]) {
    if (out.length >= limit) break
    out.push({ kind: 'field', label: f.path, insert: f.path })
  }
  return out
}

/** Values known without asking the server: enum and boolean values, ages. */
export function localValues(
  field: QuerySchemaField | undefined,
  ctx: CaretContext
): Completion[] | null {
  if (!field) return null
  const p = ctx.prefix.toLowerCase()
  let pool: readonly string[] | null = null
  if (field.type === 'boolean') pool = ['true', 'false']
  else if (field.type === 'enum' && field.enum) pool = field.enum
  else if (field.type === 'date-time') pool = AGE_VALUES
  if (!pool) return null
  return pool
    .filter((v) => v.toLowerCase().startsWith(p) && v.toLowerCase() !== p)
    .map((v) => ({ kind: 'value' as const, label: v, insert: v }))
}

/** Quotes a value that would not read back as one bare value. */
export function quoteValue(v: string): string {
  return /^[^\s"(),\\]+$/.test(v) && !v.startsWith('-') && !v.includes('..')
    ? v
    : `"${v.replace(/[\\"]/g, '\\$&')}"`
}

/** The text with the completion applied, and the caret after it. */
export function applyCompletion(
  text: string,
  ctx: CaretContext,
  insert: string
): { text: string; caret: number } {
  const next = text.slice(0, ctx.start) + insert + text.slice(ctx.end)
  return { text: next, caret: ctx.start + insert.length }
}

/** The text with one problem's range replaced by a fix. */
export function applyFix(text: string, start: number, end: number, fix: string): string {
  return text.slice(0, start) + fix + text.slice(end)
}

/** Counts the way lists show them: exact up to 10,000, then "10,000+". */
export const COUNT_CAP = 10000

export function formatCount(n: number, locale?: string): string {
  return n > COUNT_CAP ? `${COUNT_CAP.toLocaleString(locale)}+` : n.toLocaleString(locale)
}
