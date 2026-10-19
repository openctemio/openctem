/**
 * The mode radios show the mode in force. When the platform enforces a mode
 * over the organization's choice, that mode is the selected one (read-only)
 * and the organization's own choice is a note, never the selected value.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const gov = vi.hoisted(() => ({ data: null as unknown }))
vi.mock('@/lib/api/scan-approval-hooks', () => ({
  useScanGovernance: () => ({
    data: gov.data,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  saveScanGovernanceMode: vi.fn(),
  saveScanGovernanceRules: vi.fn(),
}))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ isOwner: () => true, isAdmin: () => true }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const { ScanApprovalSettings } = await import('../scan-approval-settings')

const base = {
  rules: [],
  selectable_modes: ['off', 'on', 'strict'],
  pending_expiry_days: 7,
}

describe('ScanApprovalSettings', () => {
  it('shows the enforced mode selected and the organization choice as a note', () => {
    gov.data = { ...base, mode: 'strict', organization_mode: 'off', source: 'platform' }
    render(<ScanApprovalSettings />)
    expect(screen.getByRole('radio', { name: /Strict/ })).toBeChecked()
    expect(screen.getByRole('radio', { name: /Off/ })).not.toBeChecked()
    expect(screen.getByText(/Your organization chose Off/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
  })

  it('without enforcement the radios show the organization choice, editable by an owner', () => {
    gov.data = { ...base, mode: 'on', organization_mode: 'on', source: 'organization' }
    render(<ScanApprovalSettings />)
    expect(screen.getByRole('radio', { name: /^On/ })).toBeChecked()
    expect(screen.getByRole('radio', { name: /^On/ })).toBeEnabled()
    expect(screen.queryByText(/Your organization chose/)).toBeNull()
  })
})
