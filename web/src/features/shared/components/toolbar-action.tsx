'use client'

import type { LucideIcon } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

/**
 * A labelled action at the end of a list toolbar (Export CSV). Below a 42rem
 * toolbar (a phone) it is an icon: its name stays the accessible name and
 * shows in a tooltip, so the end actions keep to about 40% of the phone
 * toolbar's second line and the filter tokens keep their room
 * (web/docs/ui-style-contract.md, list state).
 */
export function ToolbarAction({
  icon: Icon,
  label,
  onClick,
  disabled,
}: {
  icon: LucideIcon
  label: string
  onClick: () => void
  disabled?: boolean
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          iconOnlyBelow="@2xl/toolbar"
          data-slot="toolbar-action"
          onClick={onClick}
          disabled={disabled}
        >
          <Icon className="h-4 w-4 @2xl/toolbar:me-2" aria-hidden />
          <span className="sr-only @2xl/toolbar:not-sr-only">{label}</span>
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}
