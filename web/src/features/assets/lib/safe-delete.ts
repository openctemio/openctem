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
import { defaultT, type TFn } from './default-t'

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

/** Archives the given assets and reports the result. */
export async function archiveAndReport(
  ids: string[],
  onChanged?: () => unknown,
  t: TFn = defaultT
) {
  const res = await bulkArchiveAssets(ids)
  const archived = res.archived.length
  const failed = res.failed.length
  if (archived > 0) {
    toast.success(
      archived === 1
        ? t('assets.safeDelete.archivedOne', 'Archived 1 asset; its findings are kept')
        : t('assets.safeDelete.archived', 'Archived {count} assets; their findings are kept', {
            count: archived,
          })
    )
  }
  if (failed > 0) {
    toast.error(
      failed === 1
        ? t('assets.safeDelete.archiveFailedOne', 'Could not archive 1 asset')
        : t('assets.safeDelete.archiveFailed', 'Could not archive {count} assets', {
            count: failed,
          })
    )
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
  onChanged?: () => unknown,
  t: TFn = defaultT
): Promise<'deleted' | 'refused' | 'failed'> {
  try {
    await deleteAsset(id)
    toast.success(t('assets.safeDelete.deleted', '{name} deleted', { name }))
    await onChanged?.()
    return 'deleted'
  } catch (err) {
    if (isAssetHasFindingsError(err)) {
      const n = findingCountOf(err)
      toast.warning(
        n === undefined
          ? t(
              'assets.safeDelete.refused',
              '{name} was not deleted: it has findings. Archive it to hide it and keep its finding history.',
              { name }
            )
          : t(
              'assets.safeDelete.refusedCount',
              '{name} was not deleted: it has {count} findings. Archive it to hide it and keep its finding history.',
              { name, count: n }
            ),
        {
          duration: 15000,
          action: {
            label: t('assets.safeDelete.archiveAction', 'Archive'),
            onClick: () => void archiveAndReport([id], onChanged, t),
          },
        }
      )
      return 'refused'
    }
    toast.error(
      getErrorMessage(err, t('assets.safeDelete.deleteFailed', 'Failed to delete {name}', { name }))
    )
    return 'failed'
  }
}

/** Reports a bulk delete: deleted, refused (with an Archive action), failed. */
export function reportBulkDelete(
  outcome: BulkDeleteOutcome,
  onChanged?: () => unknown,
  t: TFn = defaultT
) {
  const deleted = outcome.deleted.length
  if (deleted > 0) {
    toast.success(
      deleted === 1
        ? t('assets.safeDelete.bulkDeletedOne', 'Deleted 1 asset')
        : t('assets.safeDelete.bulkDeleted', 'Deleted {count} assets', { count: deleted })
    )
  }
  if (outcome.refused.length > 0) {
    const refused = [...outcome.refused]
    toast.warning(
      refused.length === 1
        ? t(
            'assets.safeDelete.bulkRefusedOne',
            '1 asset was not deleted because it has findings. Archive it to keep the finding history.'
          )
        : t(
            'assets.safeDelete.bulkRefused',
            '{count} assets were not deleted because they have findings. Archive them to keep the finding history.',
            { count: refused.length }
          ),
      {
        duration: 15000,
        action: {
          label: t('assets.safeDelete.archiveAction', 'Archive'),
          onClick: () => void archiveAndReport(refused, onChanged, t),
        },
      }
    )
  }
  const failed = outcome.failed.length
  if (failed > 0) {
    toast.error(
      failed === 1
        ? t('assets.safeDelete.bulkFailedOne', 'Failed to delete 1 asset')
        : t('assets.safeDelete.bulkFailed', 'Failed to delete {count} assets', { count: failed })
    )
  }
}
