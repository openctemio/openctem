'use client'

import { Plus } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Can, Permission } from '@/lib/permissions'

/**
 * The "create a scan workflow" button. It is gated on the scan workflows write
 * permission (the one POST /scan-workflows checks), not on the automations
 * permission: a member who can write scan workflows can create one, and a member
 * who can only edit automations cannot.
 */
export function NewScanWorkflowButton({
  label,
  onClick,
  compact = false,
  variant,
}: {
  label: string
  onClick: () => void
  /**
   * In a page header: an icon button that keeps its name on a phone, the
   * label from 768 px.
   */
  compact?: boolean
  /** `outline` beside the page header's filled one (one filled button per screen). */
  variant?: 'outline'
}) {
  return (
    <Can permission={Permission.ScanWorkflowsWrite} mode="disable">
      {compact ? (
        <Button size="sm" iconOnlyBelow="md" onClick={onClick} aria-label={label}>
          <Plus className="h-4 w-4 md:me-2" aria-hidden />
          <span className="sr-only md:not-sr-only">{label}</span>
        </Button>
      ) : (
        <Button size="sm" variant={variant} onClick={onClick}>
          <Plus className="me-2 h-4 w-4" />
          {label}
        </Button>
      )}
    </Can>
  )
}
