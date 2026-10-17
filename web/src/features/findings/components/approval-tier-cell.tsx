'use client'

/**
 * A request's approval tier and, while pending, its sign-off progress
 * (finding requests and group exceptions alike).
 */

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { tierHelp, tierLabel } from '../lib/approval-policy'

export interface TierProgress {
  tier?: string
  status: string
  approvals_required?: number
  approvals_collected?: number
}

export function ApprovalTierCell({
  approval,
  showSingleProgress = false,
}: {
  approval: TierProgress
  /** Show "0 of 1" too (a group exception always names its progress). */
  showSingleProgress?: boolean
}) {
  const { t } = useTranslation()
  if (!approval.tier) return <span className="text-sm text-muted-foreground">-</span>
  const required = approval.approvals_required ?? 0
  const collected = approval.approvals_collected ?? 0
  return (
    <div className="flex flex-col items-start gap-1">
      <Badge
        variant="outline"
        className={cn(
          'text-xs whitespace-nowrap',
          (approval.tier === 'security' || approval.tier === 'dual') &&
            'border-primary/40 text-primary'
        )}
        title={tierHelp(t, approval.tier)}
      >
        {tierLabel(t, approval.tier)}
      </Badge>
      {approval.status === 'pending' && (required > 1 || (showSingleProgress && required > 0)) && (
        <span className="text-xs text-muted-foreground whitespace-nowrap">
          {t('findings.approvals.progress', '{collected} of {required} approvals', {
            collected,
            required,
          })}
        </span>
      )}
    </div>
  )
}
