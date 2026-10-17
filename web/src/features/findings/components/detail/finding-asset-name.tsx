import Link from '@/components/link'
import { assetDetailHref, isLinkableAssetId } from '../../lib/asset-link'

/**
 * An affected asset's name in a finding header. A real inventory asset links
 * to its full page; a free-text target (no routable id) stays plain text.
 */
export function FindingAssetName({ id, name }: { id?: string | null; name?: string | null }) {
  if (!name) return null
  if (!isLinkableAssetId(id)) return <>{name}</>
  return (
    <Link href={assetDetailHref(id)} className="hover:underline focus-visible:underline">
      {name}
    </Link>
  )
}
