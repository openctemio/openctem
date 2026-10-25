'use client'

import useSWR from 'swr'
import { ShieldCheck } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { useTenant } from '@/context/tenant-provider'
import { get } from '@/lib/api/client'
import { Permission } from '@/lib/permissions'

/** The caller's review queue, counted by the approvals API. */
export const REVIEW_QUEUE_URL = '/api/v1/approvals?queue=review&per_page=1'

interface ReviewQueue {
  total?: number
  queue_counts?: Record<string, number>
}

/** The count of requests waiting for the caller's decision. */
export function reviewCount(res: ReviewQueue | undefined): number {
  const n = res?.queue_counts?.review ?? res?.total ?? 0
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0
}

/**
 * The top bar's approvals button: how many requests wait for the caller's
 * decision, opening My Work on that queue. Only for people who may approve;
 * the count comes from the same API as the queue (its own scope rules).
 */
export function HeaderApprovals() {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const { currentTenant } = useTenant()
  const can = hasPermission(Permission.FindingsApprove)
  const { data } = useSWR<ReviewQueue>(can && currentTenant?.id ? REVIEW_QUEUE_URL : null, get, {
    refreshInterval: 120_000,
    revalidateOnFocus: true,
  })
  if (!can) return null
  const n = reviewCount(data)
  const label =
    n > 0
      ? t('nav.header.approvals', 'Awaiting your decision: {n}', { n })
      : t('nav.header.approvalsNone', 'Nothing awaits your decision')
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button asChild variant="ghost" size="icon" className="relative size-8" aria-label={label}>
          <Link href="/my-work?tab=review" data-slot="header-approvals">
            <ShieldCheck className="size-4.5" aria-hidden />
            {n > 0 && (
              <span className="bg-signal text-signal-ink absolute -end-0.5 -top-0.5 min-w-4 rounded-full px-1 text-center text-[11px] leading-4 font-semibold tabular-nums">
                {n > 99 ? '99+' : n}
              </span>
            )}
          </Link>
        </Button>
      </TooltipTrigger>
      <TooltipContent side="bottom" className="text-xs">
        {label}
      </TooltipContent>
    </Tooltip>
  )
}
