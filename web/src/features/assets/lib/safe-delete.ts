/**
 * Safe asset delete (owner decision O3).
 *
 * The API refuses to delete an asset that has findings (409, details.reason
 * "asset_has_findings"): deleting it would erase its finding history, SLA
 * evidence and remediation records. Archive it instead (POST
 * /assets/{id}/archive). An asset without findings is soft-deleted: it leaves
 * every list and its name can be used again.
 *
 * Every delete in the UI goes through these helpers so the refusal is shown
 * the same way everywhere, with Archive offered.
 */

import { toast } from 'sonner'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { archiveAsset, deleteAsset } from '../hooks/use-assets'

export const ASSET_HAS_FINDINGS = 'asset_has_findings'

/** True when the API refused a delete because the asset has findings. */
export function isAssetHasFindingsError(err: unknown): err is ApiClientError {
  return (
    err instanceof ApiClientError &&
    err.statusCode === 409 &&
    err.details?.reason === ASSET_HAS_FINDINGS
  )
}

function findingCountOf(err: ApiClientError): number | undefined {
  const n = err.details?.finding_count
  return typeof n === 'number' ? n : undefined
}

export interface BulkDeleteOutcome {
  /** Deleted (soft delete). */
  deleted: string[]
  /** Refused because the asset has findings: offer Archive. */
  refused: string[]
  /** Failed for another reason. */
  failed: string[]
}

export interface BulkArchiveOutcome {
  archived: string[]
  failed: string[]
}

const BATCH_SIZE = 5

async function inBatches(ids: string[], run: (id: string) => Promise<unknown>) {
  const settled: PromiseSettledResult<unknown>[] = []
  for (let i = 0; i < ids.length; i += BATCH_SIZE) {
    settled.push(...(await Promise.allSettled(ids.slice(i, i + BATCH_SIZE).map((id) => run(id)))))
  }
  return settled
}

/** Deletes each asset (5 at a time) and reports which were deleted, refused or failed. */
export async function bulkDeleteAssetsSafely(ids: string[]): Promise<BulkDeleteOutcome> {
  const settled = await inBatches(ids, deleteAsset)
  const out: BulkDeleteOutcome = { deleted: [], refused: [], failed: [] }
  settled.forEach((r, i) => {
    if (r.status === 'fulfilled') out.deleted.push(ids[i])
    else if (isAssetHasFindingsError(r.reason)) out.refused.push(ids[i])
    else out.failed.push(ids[i])
  })
  return out
}

/** Archives each asset (5 at a time). */
export async function bulkArchiveAssets(ids: string[]): Promise<BulkArchiveOutcome> {
  const settled = await inBatches(ids, archiveAsset)
  const out: BulkArchiveOutcome = { archived: [], failed: [] }
  settled.forEach((r, i) => (r.status === 'fulfilled' ? out.archived : out.failed).push(ids[i]))
  return out
}

function plural(n: number, word: string) {
  return `${n} ${word}${n === 1 ? '' : 's'}`
}

/** Archives the given assets and reports the result. */
export async function archiveAndReport(ids: string[], onChanged?: () => unknown) {
  const res = await bulkArchiveAssets(ids)
  if (res.archived.length > 0) {
    toast.success(`Archived ${plural(res.archived.length, 'asset')}; their findings are kept`)
  }
  if (res.failed.length > 0) {
    toast.error(`Could not archive ${plural(res.failed.length, 'asset')}`)
  }
  await onChanged?.()
  return res
}

/**
 * Deletes one asset. When it is refused because the asset has findings, says
 * so and offers Archive. Returns what happened.
 */
export async function deleteAssetSafely(
  id: string,
  name: string,
  onChanged?: () => unknown
): Promise<'deleted' | 'refused' | 'failed'> {
  try {
    await deleteAsset(id)
    toast.success(`${name} deleted`)
    await onChanged?.()
    return 'deleted'
  } catch (err) {
    if (isAssetHasFindingsError(err)) {
      const n = findingCountOf(err)
      toast.warning(
        `${name} was not deleted: it has ${n !== undefined ? plural(n, 'finding') : 'findings'}. Archive it to hide it and keep its finding history.`,
        {
          duration: 15000,
          action: { label: 'Archive', onClick: () => void archiveAndReport([id], onChanged) },
        }
      )
      return 'refused'
    }
    toast.error(getErrorMessage(err, `Failed to delete ${name}`))
    return 'failed'
  }
}

/** Reports a bulk delete: deleted, refused (with an Archive action), failed. */
export function reportBulkDelete(outcome: BulkDeleteOutcome, onChanged?: () => unknown) {
  if (outcome.deleted.length > 0) {
    toast.success(`Deleted ${plural(outcome.deleted.length, 'asset')}`)
  }
  if (outcome.refused.length > 0) {
    const refused = [...outcome.refused]
    toast.warning(
      `${plural(refused.length, 'asset')} not deleted because ${refused.length === 1 ? 'it has' : 'they have'} findings. Archive ${refused.length === 1 ? 'it' : 'them'} to keep the finding history.`,
      {
        duration: 15000,
        action: { label: 'Archive', onClick: () => void archiveAndReport(refused, onChanged) },
      }
    )
  }
  if (outcome.failed.length > 0) {
    toast.error(`Failed to delete ${plural(outcome.failed.length, 'asset')}`)
  }
}
