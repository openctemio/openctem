/**
 * "Select all N that match" on the findings list: a change applied by the
 * server to every finding the list's filter selects
 * (server/docs/architecture/findings-bulk-by-filter.md). The server compiles
 * the filter as the caller (tenant, data scope, permissions), refuses a count
 * other than the one the user confirmed, and re-checks every finding when it
 * applies the change; the client only sends the list's own filter.
 */

import { get, post } from '@/lib/api/client'
import type { BulkFindingResult } from './bulk-result'

/** The server's cap for one change by filter. */
export const BULK_BY_FILTER_MAX = 10_000

/** Params that are not part of a selection; the server refuses them. */
const NOT_A_SELECTION = ['page', 'per_page', 'cursor', 'sort', 'include']

/**
 * The list's filter as the by-filter body's `filter`, or null when the list
 * cannot be selected by filter: a saved view (`view`) or a query only the list
 * resolves (`fq`) would be refused, so the page offers no "Select all".
 */
export function selectionFilter(params: URLSearchParams): Record<string, string> | null {
  if (params.has('view') || params.has('fq')) return null
  const filter: Record<string, string> = {}
  for (const [name, value] of params) {
    if (NOT_A_SELECTION.includes(name)) continue
    filter[name] = value
  }
  return filter
}

/** An operation as `GET /api/v1/operations/{id}` returns it. */
export interface BulkOperation {
  id: string
  status: 'running' | 'succeeded' | 'failed' | 'interrupted'
  total: number
  processed?: number
  succeeded: number
  skipped: number
  failed: number
  items?: { id: string; outcome: string; reason?: string }[]
  error?: string
}

const POLL_MS = 1500
// The server ends a run after 30 minutes; stop reading a little after that.
const POLL_LIMIT_MS = 32 * 60 * 1000

/**
 * Starts the change and waits for its operation to end (in the request up to
 * 1,000 findings; above that the server runs it in the background and the
 * client reads it back every 1.5 s). Errors (409 SELECTION_CHANGED with
 * `details.count`, 403 STEP_UP_REQUIRED handled by `post`, 429 ...) are thrown
 * as the API client's errors.
 */
export async function runFindingsBulkByFilter(
  verb: 'status' | 'assignee',
  req: {
    filter: Record<string, string>
    expectedCount: number
    body: Record<string, unknown>
  },
  opts: { pollMs?: number; sleep?: (ms: number) => Promise<void> } = {}
): Promise<BulkOperation> {
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)))
  const pollMs = opts.pollMs ?? POLL_MS
  const res = await post<{ operation: BulkOperation }>(`/api/v1/findings/bulk/by-filter/${verb}`, {
    ...req.body,
    filter: req.filter,
    expected_count: req.expectedCount,
    // One key per confirmed change: a retried request replays the operation.
    idempotency_key: crypto.randomUUID(),
  })
  let op = res.operation
  const started = Date.now()
  while (op.status === 'running' && Date.now() - started < POLL_LIMIT_MS) {
    await sleep(pollMs)
    op = await get<BulkOperation>(`/api/v1/operations/${encodeURIComponent(op.id)}`)
  }
  return op
}

/** An ended operation in the shape the bulk toasts read (`summarizeBulkResult`). */
export function operationAsBulkResult(op: BulkOperation): BulkFindingResult {
  return {
    updated: op.succeeded,
    failed: op.skipped + op.failed,
    errors: (op.items ?? [])
      .filter((i) => i.outcome !== 'succeeded')
      .map((i) => `${i.id}: ${i.reason ?? i.outcome}`),
  }
}
