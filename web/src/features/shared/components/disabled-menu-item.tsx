'use client'

import type { LucideIcon } from 'lucide-react'
import { DropdownMenuItem } from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

/**
 * A menu item the user cannot use, explaining why on hover or focus. Used by
 * hand-built menus (the members page) until they move to `ActionMenu`.
 */
export function DisabledMenuItem({
  label,
  icon: Icon,
  reason,
}: {
  label: string
  icon?: LucideIcon
  reason: string
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div tabIndex={0} aria-label={`${label}: ${reason}`}>
          <DropdownMenuItem disabled>
            {Icon && <Icon className="me-2 h-4 w-4" />}
            {label}
          </DropdownMenuItem>
        </div>
      </TooltipTrigger>
      <TooltipContent side="left">{reason}</TooltipContent>
    </Tooltip>
  )
}
