/**
 * Completion for the search box: what the caret is in (a field name, the
 * value of a condition, nothing) and what may complete it. Field names, their
 * aliases, groups and order, and enum values come from GET
 * /api/v1/query/schema (only the fields the caller may use, read once); other
 * values come from GET /api/v1/query/values. The server
 * parser is the authority on validity: this only reads the text near the
 * caret.
 */

import type { QuerySchemaField } from '../api/query-api'
import { formatNumber } from '@/lib/app-locale'

export const SHORT_KEYWORDS = ['AND', 'OR', 'NOT'] as const

/** Ages offered for time fields ("last_seen_at<7d"). */
export const AGE_VALUES = ['1d', '7d', '30d', '90d'] as const

export type CompletionKind = 'field' | 'operator' | 'value' | 'keyword' | 'recent'

export interface Completion {
  kind: CompletionKind
  label: string
  insert: string
  count?: number
  /** The schema field a field or operator row is about (its description, type). */
  field?: QuerySchemaField
  /** The heading a field row sits under while nothing is typed. */
  group?: string
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

const CONDITION = /^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*(>=|<=|!=|=|:|>|<|~)([\s\S]*)$/ // separator-ok: regex alternation, not a text separator
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

/** Every name a query may use for a field: its path, then its aliases. */
export function fieldNames(f: QuerySchemaField): string[] {
  return [f.path, ...(f.aliases ?? [])]
}

/** The name a person types for a field: its shortest alias when shorter than the path. */
export function shortName(f: QuerySchemaField): string {
  const a = f.aliases?.[0]
  return a && a.length < f.path.length ? a : f.path
}

/** The field a path or alias names (lower case), if the caller may use it. */
export function fieldByName(
  fields: QuerySchemaField[],
  name: string | undefined
): QuerySchemaField | undefined {
  if (!name) return undefined
  return fields.find((f) => f.path === name) ?? fields.find((f) => f.aliases?.includes(name))
}

/**
 * Field names, operators and keywords for the field at the caret. With
 * nothing typed every field is offered in the schema's order (the fields
 * people filter by first, record ids last), each under its group. With a
 * prefix: fields with a name starting with it, then fields with a name
 * containing it, in the schema's order, at most `limit`; a row shows the
 * shortest name that matches.
 */
export function fieldCompletions(
  ctx: CaretContext,
  fields: QuerySchemaField[],
  limit = 10
): Completion[] {
  const p = ctx.prefix.toLowerCase()
  if (!p) {
    return fields.map((f) => ({
      kind: 'field',
      label: shortName(f),
      insert: shortName(f),
      field: f,
      group: f.group ?? 'more',
    }))
  }
  const exact = fieldByName(fields, p)
  if (exact) {
    return shortOperators(exact).map((op) => ({
      kind: 'operator',
      label: p + op,
      insert: p + op,
      field: exact,
    }))
  }
  const out: Completion[] = []
  for (const k of SHORT_KEYWORDS) {
    if (k.toLowerCase().startsWith(p) && k.toLowerCase() !== p)
      out.push({ kind: 'keyword', label: k, insert: k + ' ' })
  }
  const starts: Completion[] = []
  const contains: Completion[] = []
  for (const f of fields) {
    const names = Array.from(new Set([shortName(f), ...fieldNames(f)]))
    const start = names.find((n) => n.startsWith(p))
    const within = start ? undefined : names.find((n) => n.includes(p))
    const name = start ?? within
    if (!name) continue
    ;(start ? starts : contains).push({ kind: 'field', label: name, insert: name, field: f })
  }
  for (const c of [...starts, ...contains]) {
    if (out.length >= limit) break
    out.push(c)
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

/** Words the query grammar reads as keywords, so a value spelled like one is quoted. */
const RESERVED_WORDS = new Set(['and', 'or', 'not', 'in', 'where', 'findings', 'assets', 'scans'])

/**
 * Quotes a value so it reads back as exactly one value. Only plain words made
 * of letters, digits, `_`, `.` and `-` stay bare; operators, parentheses,
 * commas, whitespace and reserved words are quoted, with `"` and `\` escaped
 * (the only escapes the grammar has). A string cannot hold a control
 * character, so those become a space.
 */
export function quoteValue(v: string): string {
  const bare =
    /^[A-Za-z0-9_.-]+$/.test(v) &&
    !v.startsWith('-') &&
    !v.includes('..') &&
    !RESERVED_WORDS.has(v.toLowerCase())
  if (bare) return v

  return `"${v.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/[\\"]/g, '\\$&')}"`
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

/** A problem found without asking the server, with its range in the text. */
export interface LocalProblem {
  code: 'unclosed_quote' | 'unclosed_paren' | 'extra_paren'
  start: number
  end: number
}

/**
 * Checks what can be checked while typing, in the browser: quotes and
 * parentheses that do not pair up. Field names, operators and values are the
 * server's to judge (it knows short names and the caller's own fields), once,
 * when the text is applied.
 */
export function localProblem(text: string): LocalProblem | null {
  const open: number[] = []
  let quote = -1
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (quote >= 0) {
      if (c === '\\') i++
      else if (c === '"') quote = -1
      continue
    }
    if (c === '"') quote = i
    else if (c === '(') open.push(i)
    else if (c === ')') {
      if (open.length === 0) return { code: 'extra_paren', start: i, end: i + 1 }
      open.pop()
    }
  }
  if (quote >= 0) return { code: 'unclosed_quote', start: quote, end: quote + 1 }
  if (open.length > 0) {
    const at = open[open.length - 1]
    return { code: 'unclosed_paren', start: at, end: at + 1 }
  }
  return null
}

/** Counts the way lists show them: exact up to 10,000, then "10,000+". */
export const COUNT_CAP = 10000

export function formatCount(n: number, _locale?: string): string {
  return n > COUNT_CAP ? `${formatNumber(COUNT_CAP)}+` : formatNumber(n)
}
