'use client'

import { ShieldCheck } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Counter } from '@/components/ui/counter'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { usePendingApprovalCount } from '@/hooks/use-dynamic-badges'
import { Permission } from '@/lib/permissions'
import { HEADER_BADGE, HEADER_ICON_BUTTON } from './header-controls'

/**
 * The top bar's approvals button: the finding approval requests waiting for
 * a decision in the caller's scope, opening the approvals inbox that lists
 * exactly them. Only for people who may approve. The count is the one the
 * session bootstrap already carries (no request of its own).
 */
export function HeaderApprovals() {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const can = hasPermission(Permission.FindingsApprove)
  const n = usePendingApprovalCount(can) ?? 0
  if (!can) return null
  const label =
    n > 0
      ? t('nav.header.approvals', 'Pending approvals: {n}', { n })
      : t('nav.header.approvalsNone', 'No pending approvals')
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          asChild
          variant="ghost"
          size="icon"
          className={HEADER_ICON_BUTTON}
          aria-label={label}
        >
          <Link href="/findings/approvals" data-slot="header-approvals">
            <ShieldCheck aria-hidden />
            {n > 0 && <Counter value={n} emphasis size="badge" className={HEADER_BADGE} />}
          </Link>
        </Button>
      </TooltipTrigger>
      <TooltipContent side="bottom">{label}</TooltipContent>
    </Tooltip>
  )
}
