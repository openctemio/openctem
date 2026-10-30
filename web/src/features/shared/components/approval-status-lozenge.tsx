'use client'

import { StatusLozenge } from '@/components/ui/status-lozenge'
import { APPROVAL_TONE, UNKNOWN_APPROVAL } from '../lib/approval-tone'

/**
 * The state of an approval request as the shared workflow lozenge. The caller
 * passes the translated label (each domain keeps its own wording).
 */
export function ApprovalStatusLozenge({
  status,
  label,
  className,
}: {
  status: string
  label: string
  className?: string
}) {
  const cfg = APPROVAL_TONE[status] ?? UNKNOWN_APPROVAL
  return (
    <StatusLozenge
      tone={cfg.tone}
      icon={cfg.icon}
      label={label}
      value={status}
      className={className}
    />
  )
}
