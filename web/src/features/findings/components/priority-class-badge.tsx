'use client'

import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import type { PriorityClass } from '../types/finding.types'
import { PRIORITY_CLASS_CONFIG } from '../types/finding.types'
import { PriorityClassSla } from '@/features/sla/components/priority-class-sla'

interface PriorityClassBadgeProps {
  priorityClass: PriorityClass
  showTooltip?: boolean
  /** The finding's asset, so the tooltip states that asset's SLA window. */
  assetId?: string | null
  className?: string
}

export function PriorityClassBadge({
  priorityClass,
  showTooltip = true,
  assetId,
  className,
}: PriorityClassBadgeProps) {
  const config = PRIORITY_CLASS_CONFIG[priorityClass]

  const badge = (
    <Badge className={cn(config.color, config.textColor, 'font-mono font-bold text-xs', className)}>
      {config.label}
    </Badge>
  )

  if (!showTooltip) return badge

  return (
    <Tooltip>
      <TooltipTrigger asChild>{badge}</TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">
        <p className="font-medium">{config.description}</p>
        <PriorityClassSla
          priorityClass={priorityClass}
          assetId={assetId}
          className="mt-1 block text-xs text-muted-foreground"
        />
      </TooltipContent>
    </Tooltip>
  )
}
