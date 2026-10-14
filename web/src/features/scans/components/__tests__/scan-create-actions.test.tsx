import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { Permission } from '@/lib/permissions'
import { ScanCreateActions } from '../scans-section-tabs'

let granted: string[] = []
vi.mock('@/context/permission-provider', async (orig) => ({
  ...(await orig<typeof import('@/context/permission-provider')>()),
  usePermissionsSafe: () => ({ permissions: granted, isLoading: false }),
}))
vi.mock('@/context/tenant-provider', async (orig) => ({
  ...(await orig<typeof import('@/context/tenant-provider')>()),
  useTenant: () => ({ currentTenant: { id: 't1', role: 'member' } }),
}))
vi.mock('../new-scan/new-scan-dialog', () => ({ NewScanDialog: () => null }))
vi.mock('../quick-scan-dialog', () => ({ QuickScanDialog: () => null }))

// The API runs a quick scan only for scans:write AND scans:execute (it
// creates and starts a run); the button asked for scans:write alone, so a
// member without execute got a 403 on every quick scan.
const btn = (label: string) => screen.getByText(label).closest('button')

describe('ScanCreateActions', () => {
  it('offers Quick scan only with scans:write and scans:execute', () => {
    granted = [Permission.ScansWrite]
    const { unmount } = render(<ScanCreateActions />)
    expect(btn('Quick scan')).toBeDisabled()
    expect(btn('New scan')).toBeEnabled()
    unmount()

    granted = [Permission.ScansWrite, Permission.ScansExecute]
    render(<ScanCreateActions />)
    expect(btn('Quick scan')).toBeEnabled()
  })
})
