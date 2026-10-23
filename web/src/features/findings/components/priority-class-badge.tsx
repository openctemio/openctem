'use client'

import { useTranslation } from '@/context/i18n-provider'
import { PriorityBadge } from '@/components/ui/priority-badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import type { PriorityClass } from '../types/finding.types'
import { PRIORITY_CLASS_CONFIG } from '../types/finding.types'
import { PriorityClassSla } from '@/features/sla/components/priority-class-sla'

interface PriorityClassBadgeProps {
  /** The finding's class; null or missing renders the "not prioritised" dash. */
  priorityClass: PriorityClass | null | undefined
  /** Add the class name ("P0 · Immediate"). */
  showWord?: boolean
  showTooltip?: boolean
  /** The finding's asset, so the tooltip states that asset's SLA window. */
  assetId?: string | null
  className?: string
}

/** PriorityBadge with the class meaning and its SLA window as a tooltip. */
export function PriorityClassBadge({
  priorityClass,
  showTooltip = true,
  showWord,
  assetId,
  className,
}: PriorityClassBadgeProps) {
  const { t } = useTranslation()
  const badge = (
    <PriorityBadge priorityClass={priorityClass} showWord={showWord} className={className} />
  )

  if (!priorityClass || !showTooltip) return badge
  const config = PRIORITY_CLASS_CONFIG[priorityClass]

  return (
    <Tooltip>
      <TooltipTrigger asChild>{badge}</TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">
        <p className="font-medium">
          {t(`findings.priorityClass.${priorityClass}`, config.description)}
        </p>
        <PriorityClassSla
          priorityClass={priorityClass}
          assetId={assetId}
          className="mt-1 block text-xs text-muted-foreground"
        />
      </TooltipContent>
    </Tooltip>
  )
}
