import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { EditRoleSheet } from '../edit-role-sheet'
import type { Role } from '@/features/access-control'

const updateRole = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))
vi.mock('@/features/access-control', async (orig) => ({
  ...(await orig<typeof import('@/features/access-control')>()),
  useUpdateRole: () => ({ updateRole, isUpdating: false }),
  useTenantPermissionModules: () => ({ modules: [], isLoading: false }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const role = (fullData: boolean) =>
  ({
    id: 'r1',
    name: 'Analyst',
    slug: 'analyst',
    description: '',
    is_system: false,
    hierarchy_level: 50,
    has_full_data_access: fullData,
    permissions: ['findings:read'],
    permission_count: 1,
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
  }) as unknown as Role

describe('EditRoleSheet widening', () => {
  it('asks before giving every holder full data access, and saves after confirming', async () => {
    updateRole.mockClear()
    const user = userEvent.setup()
    render(<EditRoleSheet role={role(false)} open onOpenChange={vi.fn()} />)
    await user.click(screen.getByRole('switch', { name: 'Full data access' }))
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Give everyone with Analyst more access?')
    expect(dialog).toHaveTextContent('every asset')
    expect(updateRole).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Save and widen role' }))
    await waitFor(() => expect(updateRole).toHaveBeenCalled())
  })

  it('saves a narrowing change without asking', async () => {
    updateRole.mockClear()
    const user = userEvent.setup()
    render(<EditRoleSheet role={role(true)} open onOpenChange={vi.fn()} />)
    await user.click(screen.getByRole('switch', { name: 'Full data access' }))
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(updateRole).toHaveBeenCalled())
    expect(screen.queryByRole('alertdialog')).toBeNull()
  })
})
