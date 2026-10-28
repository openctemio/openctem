/**
 * A pasted list for "Add to scope": split one text box into values, detect
 * each one's kind with the same detector the single path uses, drop
 * duplicates, flag what is not recognised, and send the rest to
 * POST /scope/targets/bulk in batches of its 200-item limit. Pure helpers;
 * the server still decides every entry.
 */

import type {
  ApiBulkScopeTargetsResponse,
  BulkCreateScopeTargetsInput,
  BulkScopeTargetItemInput,
} from '../api/scope-api.types'
import { detectScopeKind, type ScopeKind } from '../components/scope-target-type'
import { patternForCoverage, wildcardApex } from './scope-entry'

/** The most values one paste may hold. */
export const MAX_LIST_VALUES = 1000
/** The bulk endpoint's limit per request. */
export const BULK_BATCH_SIZE = 200
/** The longest pattern the endpoint accepts. */
const MAX_PATTERN = 500

/** Values in a pasted text: newline, comma, semicolon, tab or space separated. */
export function splitScopeValues(raw: string): string[] {
  return raw
    .split(/[\s,;]+/)
    .map((v) => v.replace(/^["']+|["']+$/g, '').trim())
    .filter(Boolean)
}

export type ScopeListIssue = 'unrecognized' | 'too_long'

export interface ScopeListRow {
  /** What was typed (the first spelling of a duplicate). */
  raw: string
  kind?: ScopeKind
  /** The pattern that is sent (a domain follows the Covers choice). */
  pattern: string
  issue?: ScopeListIssue
}

export interface ParsedScopeList {
  rows: ScopeListRow[]
  /** Values after the first of an identical pair, left out. */
  duplicates: number
  /** More values than MAX_LIST_VALUES: nothing is parsed. */
  tooMany: boolean
  total: number
}

/**
 * Parse a pasted text. `asRequest` keeps a typed domain as it is (a member's
 * request is one exact name, never a wildcard).
 */
export function parseScopeList(
  raw: string,
  coverage: 'name' | 'subdomains',
  opts: { asRequest?: boolean } = {}
): ParsedScopeList {
  const values = splitScopeValues(raw)
  if (values.length > MAX_LIST_VALUES)
    return { rows: [], duplicates: 0, tooMany: true, total: values.length }
  const seen = new Set<string>()
  const rows: ScopeListRow[] = []
  let duplicates = 0
  for (const value of values) {
    const kind = detectScopeKind(value)
    let pattern = value
    if (kind === 'domain') {
      const host = (wildcardApex(value) || value).toLowerCase().replace(/\.$/, '')
      // A request keeps what was typed, so a wildcard is refused, not narrowed.
      pattern = opts.asRequest
        ? value.toLowerCase().replace(/\.$/, '')
        : patternForCoverage(host, coverage)
    }
    const key = `${kind ?? '?'}:${kind === 'domain' ? pattern.toLowerCase() : pattern}`
    if (seen.has(key)) {
      duplicates++
      continue
    }
    seen.add(key)
    const issue: ScopeListIssue | undefined = !kind
      ? 'unrecognized'
      : pattern.length > MAX_PATTERN
        ? 'too_long'
        : undefined
    rows.push({ raw: value, kind, pattern, issue })
  }
  return { rows, duplicates, tooMany: false, total: values.length }
}

/** The text without the values that parse to `row` (the preview's Remove). */
export function removeScopeValue(
  raw: string,
  row: ScopeListRow,
  coverage: 'name' | 'subdomains',
  opts: { asRequest?: boolean } = {}
): string {
  const gone = (v: string) => {
    const one = parseScopeList(v, coverage, opts).rows[0]
    return !!one && one.pattern === row.pattern && one.kind === row.kind
  }
  return splitScopeValues(raw)
    .filter((v) => !gone(v))
    .join('\n')
}

/** The text without every row that has an issue. */
export function removeInvalidScopeValues(
  raw: string,
  coverage: 'name' | 'subdomains',
  opts: { asRequest?: boolean } = {}
): string {
  const bad = new Set(
    parseScopeList(raw, coverage, opts)
      .rows.filter((r) => r.issue)
      .map((r) => r.raw)
  )
  return splitScopeValues(raw)
    .filter((v) => !bad.has(v))
    .join('\n')
}

/** Items to send: the valid rows. */
export function itemsOf(rows: ScopeListRow[]): BulkScopeTargetItemInput[] {
  return rows
    .filter((r) => !r.issue && r.kind)
    .map((r) => ({ target_type: r.kind as string, pattern: r.pattern }))
}

/** Split into requests of at most `size` items. */
export function batchesOf<T>(items: T[], size: number = BULK_BATCH_SIZE): T[][] {
  const out: T[][] = []
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size))
  return out
}

export type BulkItemResult = NonNullable<ApiBulkScopeTargetsResponse['results']>[number]

export interface BulkListOutcome {
  results: BulkItemResult[]
  created: number
  existing: number
  refused: number
  /** Items of the batches that were not sent because a request failed. */
  unsent: BulkScopeTargetItemInput[]
  /** The error that stopped the run (never the first batch: that one throws). */
  error?: unknown
}

/**
 * Send the items in batches, one after the other. The first batch is awaited
 * alone and its failure (a cancelled step-up, a refusal of the whole request)
 * throws with nothing written; the shared client asks for the step-up once
 * and its window covers the batches after it. A failure of a later batch
 * stops the run and returns what happened so far with the items not sent.
 */
export async function submitScopeBatches(
  items: BulkScopeTargetItemInput[],
  shared: Omit<BulkCreateScopeTargetsInput, 'items'>,
  send: (input: BulkCreateScopeTargetsInput) => Promise<ApiBulkScopeTargetsResponse>
): Promise<BulkListOutcome> {
  const batches = batchesOf(items)
  const out: BulkListOutcome = { results: [], created: 0, existing: 0, refused: 0, unsent: [] }
  for (let i = 0; i < batches.length; i++) {
    let res: ApiBulkScopeTargetsResponse
    try {
      res = await send({ ...shared, items: batches[i] })
    } catch (err) {
      if (i === 0) throw err
      out.error = err
      out.unsent = batches.slice(i).flat()
      return out
    }
    out.results.push(...(res.results ?? []))
    out.created += res.created ?? 0
    out.existing += res.existing ?? 0
    out.refused += res.refused ?? 0
  }
  return out
}
