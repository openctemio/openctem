/**
 * "New scan workflow" is gated on the scan workflows write permission (the one
 * POST /scan-workflows checks), not on the automations permission.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

import { NewScanWorkflowButton } from '../new-scan-workflow-button'
import { Permission } from '@/lib/permissions'

let perms: string[] = []

vi.mock('@/lib/permissions/hooks', () => ({
  usePermissions: () => ({
    permissions: perms,
    can: (p: string) => perms.includes(p),
    canAny: (...p: string[]) => p.some((x) => perms.includes(x)),
    canAll: (...p: string[]) => p.every((x) => perms.includes(x)),
    isAtLeast: () => false,
    isLoading: false,
    tenantRole: 'member',
  }),
}))

describe('NewScanWorkflowButton', () => {
  beforeEach(() => {
    perms = []
  })

  it('is enabled for a member who can write scan workflows but not automations', () => {
    perms = [Permission.ScanWorkflowsRead, Permission.ScanWorkflowsWrite]
    render(<NewScanWorkflowButton label="New scan workflow" onClick={vi.fn()} />)
    expect(screen.getByText('New scan workflow').closest('button')).toBeEnabled()
  })

  it('is disabled for a member who can write automations but not scan workflows', () => {
    perms = [Permission.WorkflowsRead, Permission.WorkflowsWrite, Permission.ScanWorkflowsRead]
    render(<NewScanWorkflowButton label="New scan workflow" onClick={vi.fn()} />)
    expect(screen.getByText('New scan workflow').closest('button')).toBeDisabled()
  })
})
