'use client'

import { useTranslation } from '@/context/i18n-provider'
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
  const { t } = useTranslation()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge
          variant="outline"
          className={cn('shrink-0 gap-0.5 px-1.5 text-xs font-medium', className)}
          data-slot="branch-only"
        >
          <GitBranch className="h-2.5 w-2.5" aria-hidden />
          {t('findings.branchOnly.label', 'Branch only')}
        </Badge>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs text-xs">
        {t(
          'findings.branchOnly.tooltip',
          'Seen only on a feature branch. Not counted as exposure (dashboards, SLA, notifications) until the default, a protected or a release branch has it.'
        )}
      </TooltipContent>
    </Tooltip>
  )
}
