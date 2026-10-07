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
export function NewScanWorkflowButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <Can permission={Permission.ScanWorkflowsWrite} mode="disable">
      <Button size="sm" onClick={onClick}>
        <Plus className="me-2 h-4 w-4" />
        {label}
      </Button>
    </Can>
  )
}
