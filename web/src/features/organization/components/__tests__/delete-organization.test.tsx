import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const del = vi.fn()
const switchTeam = vi.fn()
const toastSuccess = vi.fn()
const toastError = vi.fn()

vi.mock('@/lib/api/client', () => ({ del: (...a: unknown[]) => del(...a) }))
vi.mock('sonner', () => ({
  toast: {
    success: (...a: unknown[]) => toastSuccess(...a),
    error: (...a: unknown[]) => toastError(...a),
  },
}))
vi.mock('@/lib/permissions', () => ({ usePermissions: () => ({ isOwner: () => true }) }))
vi.mock('@/lib/cookies', () => ({ removeCookie: vi.fn() }))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({
    currentTenant: { id: 't1', slug: 'acme', name: 'Acme' },
    tenants: [
      { id: 't1', slug: 'acme', name: 'Acme' },
      { id: 't2', slug: 'beta', name: 'Beta' },
    ],
    switchTeam: (...a: unknown[]) => switchTeam(...a),
    loadTenants: vi.fn(),
  }),
}))

import { DeleteOrganization } from '../delete-organization'
import { takeSessionFlash } from '@/lib/session-navigation'

async function confirmDelete() {
  const user = userEvent.setup()
  render(<DeleteOrganization />)
  await user.click(screen.getByRole('button', { name: /delete organization/i }))
  await user.type(screen.getByRole('textbox'), 'Acme')
  const buttons = screen.getAllByRole('button', { name: /delete/i })
  await user.click(buttons[buttons.length - 1])
}

describe('DeleteOrganization', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Object.defineProperty(window, 'location', {
      value: { replace: vi.fn() },
      writable: true,
    })
  })

  it('a failed switch after a successful delete is not reported as a failed delete', async () => {
    del.mockResolvedValue(undefined)
    switchTeam.mockRejectedValue(new Error('switch failed'))
    await confirmDelete()
    await waitFor(() => expect(window.location.replace).toHaveBeenCalled())
    expect(toastError).not.toHaveBeenCalled()
    expect(takeSessionFlash()?.title).toContain('will be deleted on')
  })

  it('says when the scheduled deletion happens and that an owner can cancel', async () => {
    del.mockResolvedValue({ status: 'pending_deletion', deletion_due_at: '2026-11-01T09:00:00Z' })
    switchTeam.mockResolvedValue(undefined)
    await confirmDelete()
    // Said on the page that loads next (the reload would drop a toast here).
    await waitFor(() => expect(window.location.replace).toHaveBeenCalled())
    const flash = takeSessionFlash()
    expect(flash?.title).toContain('Acme')
    expect(flash?.title).toContain('will be deleted on')
    expect(flash?.description).toMatch(/owner can cancel/i)
  })

  it('a failed delete is reported as a failure', async () => {
    del.mockRejectedValue(new Error('forbidden'))
    await confirmDelete()
    await waitFor(() => expect(toastError).toHaveBeenCalled())
    expect(toastSuccess).not.toHaveBeenCalled()
    expect(switchTeam).not.toHaveBeenCalled()
  })
})
