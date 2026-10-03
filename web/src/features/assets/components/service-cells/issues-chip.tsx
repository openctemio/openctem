import Link from 'next/link'
import { ShieldAlert } from 'lucide-react'
import { cn } from '@/lib/utils'
import { factChipBase } from './fact-chip'

/**
 * The statuses `assets.finding_count` counts: every finding on the asset that
 * is not `resolved` (api internal/infra/postgres/asset_repository.go, the
 * LATERAL finding aggregate). The link filters the findings list to the same
 * set, so the number on the chip is the number of rows behind it.
 */
export const UNRESOLVED_FINDING_STATUSES = [
  'new',
  'confirmed',
  'in_progress',
  'fix_applied',
  'false_positive',
  'accepted',
  'duplicate',
  'draft',
  'in_review',
  'remediation',
  'retest',
  'verified',
  'accepted_risk',
] as const

export function assetFindingsHref(assetId: string): string {
  const q = new URLSearchParams({
    assetId,
    status: UNRESOLVED_FINDING_STATUSES.join(','),
  })
  return `/findings?${q.toString()}`
}

export interface IssuesChipProps {
  assetId: string
  count: number
  className?: string
}

/**
 * "N issues found", linking to the asset's unresolved findings. Renders
 * nothing at zero: a zero is not a problem and is never coloured.
 */
export function IssuesChip({ assetId, count, className }: IssuesChipProps) {
  if (!Number.isFinite(count) || count <= 0) return null
  const label = `${count} ${count === 1 ? 'issue' : 'issues'} found`
  return (
    <Link
      href={assetFindingsHref(assetId)}
      onClick={(e) => e.stopPropagation()}
      title="Open the findings on this asset that are not resolved"
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
