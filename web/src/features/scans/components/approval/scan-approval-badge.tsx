'use client'

import { ApprovalStatusLozenge } from '@/features/shared/components/approval-status-lozenge'
import { useTranslation } from '@/context/i18n-provider'

/**
 * The scan list's approval badge (RFC-073): shown while the scan's newest
 * approval request waits, or after it was rejected. Nothing otherwise.
 */
export function ScanApprovalBadge({ status }: { status?: string | null }) {
  const { t } = useTranslation()
  if (status === 'pending') {
    return (
      <span data-testid="scan-approval-badge" className="inline-flex">
        <ApprovalStatusLozenge
          status="pending"
          label={t('scans.approval.statusPending', 'Awaiting approval')}
        />
      </span>
    )
  }
  if (status === 'rejected') {
    return (
      <span data-testid="scan-approval-badge" className="inline-flex">
        <ApprovalStatusLozenge
          status="rejected"
          label={t('scans.approval.statusRejected', 'Rejected')}
        />
      </span>
    )
  }
  return null
}
