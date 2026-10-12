import Link from '@/components/link'
import { ShieldAlert } from 'lucide-react'
import { cn } from '@/lib/utils'
import { FINDINGS_OPEN_STATUSES } from '@/features/findings/lib/list-defaults'
import { factChipBase } from './fact-chip'

/**
 * The link opens the asset's findings in the Findings list's "Open" group,
 * the same statuses its "Open" filter uses.
 *
 * The number on the chip is `assets.finding_count`, which the API counts as
 * every finding on the asset that is not `resolved` (api
 * internal/infra/postgres/asset_repository.go). That includes false
 * positives and accepted risks, so it can be higher than the open list it
 * links to; the tooltip says so rather than hiding it. Counting open
 * findings only is an API change (follow-up).
 */
export function assetFindingsHref(assetId: string): string {
  const q = new URLSearchParams({ asset_id: assetId, status: FINDINGS_OPEN_STATUSES.join(',') })
  return `/findings?${q.toString()}`
}

export interface IssuesChipProps {
  assetId: string
  count: number
  className?: string
}

/**
 * "N issues found", linking to the asset's open findings. Renders
 * nothing at zero: a zero is not a problem and is never coloured.
 */
export function IssuesChip({ assetId, count, className }: IssuesChipProps) {
  if (!Number.isFinite(count) || count <= 0) return null
  const label = `${count} ${count === 1 ? 'issue' : 'issues'} found`
  return (
    <Link
      href={assetFindingsHref(assetId)}
      onClick={(e) => e.stopPropagation()}
      title="Findings on this asset that are not resolved. Opens its open findings."
      className={cn(
        factChipBase,
        'border-transparent bg-warning/15 font-medium text-warning tabular-nums hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        className
      )}
    >
      <ShieldAlert aria-hidden="true" />
      {label}
    </Link>
  )
}
