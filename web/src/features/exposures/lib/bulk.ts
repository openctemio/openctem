/** What a bulk state change did, so the caller can report it in one place. */
export interface BulkOutcome {
  total: number
  /** Requests that succeeded, including those that went to pending approval. */
  succeeded: number
  /** Succeeded requests that now wait for a second approver (not applied yet). */
  pending: number
  failed: number
}

export const BULK_CONCURRENCY = 5

/**
 * Runs `fn` for every id with at most `concurrency` requests in flight and
 * never rejects: each id ends as fulfilled or rejected, in input order.
 */
export async function runPool<T>(
  ids: string[],
  fn: (id: string) => Promise<T>,
  concurrency = BULK_CONCURRENCY
): Promise<PromiseSettledResult<T>[]> {
  const results: PromiseSettledResult<T>[] = new Array(ids.length)
  let next = 0
  const worker = async () => {
    while (next < ids.length) {
      const i = next++
      try {
        results[i] = { status: 'fulfilled', value: await fn(ids[i]) }
      } catch (reason) {
        results[i] = { status: 'rejected', reason }
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, ids.length) }, worker))
  return results
}

export function summarizeBulk<T>(
  results: PromiseSettledResult<T>[],
  isPending: (value: T) => boolean = () => false
): BulkOutcome {
  let succeeded = 0
  let pending = 0
  for (const r of results) {
    if (r.status !== 'fulfilled') continue
    succeeded++
    if (isPending(r.value)) pending++
  }
  return { total: results.length, succeeded, pending, failed: results.length - succeeded }
}
