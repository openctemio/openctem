'use client'

import type { ReactNode } from 'react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

/**
 * Explains why a control is off. A disabled button receives no pointer or
 * focus events, so the reason sits on a focusable wrapper around it; with no
 * reason the control renders untouched.
 */
export function DisabledReason({ reason, children }: { reason?: string; children: ReactNode }) {
  if (!reason) return <>{children}</>
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex">
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent>{reason}</TooltipContent>
    </Tooltip>
  )
}
