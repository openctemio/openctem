'use client'

import { Crown, Globe } from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export interface AssetMarkersProps {
  internetFacing?: boolean
  crownJewel?: boolean
  /** False inside another control (the phone card button): no focus stops or tooltips. */
  interactive?: boolean
  className?: string
}

/**
 * The two asset facts a finding row shows beside the asset name: an
 * internet-facing globe and a crown-jewel crown. Icons with a tooltip and an
 * accessible name (no text badges), one rendering for the table cell and the
 * phone card.
 */
export function AssetMarkers({
  internetFacing,
  crownJewel,
  interactive = true,
  className,
}: AssetMarkersProps) {
  const { t } = useTranslation()
  if (!internetFacing && !crownJewel) return null
  const marks = [
    internetFacing && {
      key: 'internet',
      Icon: Globe,
      label: t('findings.list.assetInternetFacing', 'Internet-facing'),
      tone: 'text-warning',
    },
    crownJewel && {
      key: 'crown',
      Icon: Crown,
      label: t('findings.list.assetCrownJewel', 'Crown jewel'),
      tone: 'text-foreground',
    },
  ].filter(Boolean) as { key: string; Icon: typeof Globe; label: string; tone: string }[]
  return (
    <span
      data-slot="asset-markers"
      className={cn('inline-flex shrink-0 items-center gap-1', className)}
    >
      {marks.map(({ key, Icon, label, tone }) =>
        !interactive ? (
          <span key={key} data-marker={key} role="img" aria-label={label} title={label}>
            <Icon aria-hidden className={cn('size-3.5', tone)} />
          </span>
        ) : (
          <Tooltip key={key}>
            <TooltipTrigger asChild>
              <span
                data-marker={key}
                role="img"
                aria-label={label}
                tabIndex={0}
                className="inline-flex rounded-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              >
                <Icon aria-hidden className={cn('size-3.5', tone)} />
              </span>
            </TooltipTrigger>
            <TooltipContent side="top" className="text-xs">
              {label}
            </TooltipContent>
          </Tooltip>
        )
      )}
    </span>
  )
}
