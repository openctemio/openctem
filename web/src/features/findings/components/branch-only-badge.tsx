'use client'

import { GitBranch } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'

/**
 * Marks a finding seen only on a branch that does not count as exposure (a
 * feature or merge-request branch). Such findings are left out of dashboards,
 * SLA and notifications until the default, a protected or a release branch
 * sees them (api docs/architecture/branch-only-findings.md).
 */
export function BranchOnlyBadge({ className }: { className?: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge
          variant="outline"
          className={cn('h-5 shrink-0 gap-0.5 px-1.5 text-[10px] font-medium', className)}
          data-slot="branch-only"
        >
          <GitBranch className="h-2.5 w-2.5" aria-hidden />
          Branch only
        </Badge>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs text-xs">
        Seen only on a feature branch. Not counted as exposure (dashboards, SLA, notifications)
        until the default, a protected or a release branch has it.
      </TooltipContent>
    </Tooltip>
  )
}
