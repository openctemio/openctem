import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { ShieldAlert } from 'lucide-react'
import { cn } from '@/lib/utils'
import { FINDINGS_OPEN_STATUSES } from '@/features/findings/lib/list-defaults'
import { INFORMATIONAL_PARAM } from '@/features/findings/lib/quick-views'
import { STATUS_TONE_TEXT } from '@/lib/status-colors'

/**
 * The one way the console shows how many findings an asset has (research/271):
 * "N open findings", linking to that asset's open findings.
 *
 * The number is `assets.finding_count`: the asset's findings in the open set
 * (new, confirmed, in progress, fix applied), branch-only findings left out
 * (api internal/infra/postgres/asset_repository.go, OpenStatusSQL), every
 * severity. The link filters the Findings list on the same statuses (the list
 * also leaves branch-only findings out by default) and keeps informational
 * findings in, which the open list hides by default, so the list it opens
 * shows the same number.
 */
export function assetFindingsHref(assetId: string): string {
  const q = new URLSearchParams({
    asset_id: assetId,
    status: FINDINGS_OPEN_STATUSES.join(','),
    [INFORMATIONAL_PARAM]: 'true',
  })
  return `/findings?${q.toString()}`
}

export interface OpenFindingsLinkProps {
  assetId: string
  count: number
  /**
   * Only the number, for a column whose header already says "Open findings".
   * The accessible name still reads "N open findings".
   */
  compact?: boolean
  className?: string
}

/**
 * "N open findings" in the caution colour with a shield, linking to the
 * asset's open findings. Inline text, not a pill, so a card keeps one meta
 * line. The hit area reaches 44 px tall without changing the line height.
 * Renders nothing at zero: a zero is not a problem and is never coloured.
 */
export function OpenFindingsLink({ assetId, count, compact, className }: OpenFindingsLinkProps) {
  const { t } = useTranslation()
  if (!Number.isFinite(count) || count <= 0) return null
  const label =
    count === 1
      ? t('assets.openFindings.one', '1 open finding')
      : t('assets.openFindings.many', '{count} open findings', { count })
  return (
    <Link
      href={assetFindingsHref(assetId)}
      onClick={(e) => e.stopPropagation()}
      aria-label={compact ? label : undefined}
      title={t(
        'assets.openFindings.title',
        'Findings on this asset that still need work: new, confirmed, in progress or fix applied. Opens them in Findings.'
      )}
      data-slot="open-findings-link"
      className={cn(
        'relative inline-flex w-fit shrink-0 items-center gap-1 whitespace-nowrap rounded-sm text-xs font-medium leading-5 tabular-nums',
        // The caution tone (research/266), as text on the card.
        STATUS_TONE_TEXT.accepted,
        'hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        // A 44 px tall hit area on a 20 px line (touch target).
        "after:absolute after:-inset-x-1 after:-inset-y-3 after:content-['']",
        className
      )}
    >
      <ShieldAlert aria-hidden="true" className="size-3.5 shrink-0" />
      {compact ? count.toLocaleString() : label}
    </Link>
  )
}

/**
 * The cell of an "Open findings" column: the number as a link, or a muted 0.
 * Every asset table uses it, under the header `assets.col.openFindings`.
 */
export function OpenFindingsCell({ assetId, count }: { assetId: string; count: number }) {
  if (!Number.isFinite(count) || count <= 0) {
    return <span className="text-xs tabular-nums text-muted-foreground">0</span>
  }
  return <OpenFindingsLink assetId={assetId} count={count} compact />
}
