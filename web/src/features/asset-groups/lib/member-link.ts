import { assetDetailHref } from '@/features/findings/lib/asset-link'

/**
 * Where a group member row opens: the generic asset page `/assets/{id}`,
 * which renders every asset type (a repository redirects on to its richer
 * page). The type is not part of the URL. A per-type map used to send
 * members to `/assets/domains/{id}`, `/assets/hosts/{id}` and the like,
 * routes that do not exist (only the type listings do), so the click 404'd.
 */
export function groupMemberHref(assetId: string): string {
  return assetDetailHref(assetId)
}
