/**
 * POST /api/v1/assets answers a name (or address) that already exists with a
 * 409 and changes nothing. `details.existing_asset_id` names the existing
 * asset only when it is in the caller's data scope; otherwise the conflict is
 * generic and there is nothing to link to.
 */

import { toast } from 'sonner'
import { ApiClientError } from '@/lib/api/error-handler'
import { assetDetailHref, isLinkableAssetId } from '@/features/findings/lib/asset-link'

export interface DuplicateAsset {
  /** The existing asset, when the caller may see it. */
  existingAssetId?: string
}

/** The duplicate-asset conflict carried by err, or undefined for any other error. */
export function duplicateAssetConflict(err: unknown): DuplicateAsset | undefined {
  if (!(err instanceof ApiClientError) || err.statusCode !== 409) return undefined
  const id = err.details?.existing_asset_id
  return { existingAssetId: typeof id === 'string' && isLinkableAssetId(id) ? id : undefined }
}

/**
 * Shows the duplicate-asset toast when err is that conflict and returns true;
 * returns false for any other error, which the caller reports itself.
 */
export function toastIfDuplicateAsset(err: unknown, navigate: (href: string) => void): boolean {
  const dup = duplicateAssetConflict(err)
  if (!dup) return false
  const id = dup.existingAssetId
  toast.error('An asset with this name already exists', {
    description: id ? undefined : 'Nothing was created or changed.',
    action: id ? { label: 'Open it', onClick: () => navigate(assetDetailHref(id)) } : undefined,
  })
  return true
}
