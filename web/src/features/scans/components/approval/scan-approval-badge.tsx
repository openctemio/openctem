'use client'

import { ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'

/**
 * The scan list's approval badge (RFC-072): shown while the scan's newest
 * approval request waits, or after it was rejected. Nothing otherwise.
 */
export function ScanApprovalBadge({ status }: { status?: string | null }) {
  const { t } = useTranslation()
  if (status === 'pending') {
    return (
      <Badge variant="secondary" className="gap-1" data-testid="scan-approval-badge">
        <ShieldCheck className="size-3" aria-hidden />
        {t('scans.approval.statusPending', 'Awaiting approval')}
      </Badge>
    )
  }
  if (status === 'rejected') {
    return (
      <Badge variant="outline" data-testid="scan-approval-badge">
        {t('scans.approval.statusRejected', 'Rejected')}
      </Badge>
    )
  }
  return null
}
