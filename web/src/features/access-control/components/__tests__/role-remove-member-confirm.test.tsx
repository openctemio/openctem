import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { RoleDetailSheet } from '../role-detail-sheet'
import type { Role } from '@/features/access-control'

const csrfFetch = vi.hoisted(() => vi.fn())
vi.mock('@/lib/api/client', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/client')>()),
  csrfFetch,
}))
vi.mock('@/features/access-control', async (orig) => ({
  ...(await orig<typeof import('@/features/access-control')>()),
  useRoleMembers: () => ({
    members: [
      {
        id: 'm1',
        user_id: 'u1',
        tenant_id: 't1',
        role_id: 'r1',
        assigned_at: '2026-10-01T00:00:00Z',
        name: 'Lan Tran',
        email: 'lan@acme.example',
      },
    ],
    isLoading: false,
    mutate: vi.fn(),
  }),
  useTenantPermissionModules: () => ({ modules: [], isLoading: false }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { slug: 'acme' } }),
}))
vi.mock('@/features/organization', async (orig) => ({
  ...(await orig<typeof import('@/features/organization')>()),
  useMembers: () => ({ members: [{ id: 'mem1', user_id: 'u1' }] }),
}))
vi.mock('../add-member-to-role-dialog', () => ({ AddMemberToRoleDialog: () => null }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const role = {
  id: 'r1',
  name: 'Analyst',
  slug: 'analyst',
  is_system: false,
  hierarchy_level: 50,
  permissions: [],
  permission_count: 0,
  member_count: 1,
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
} as unknown as Role

describe('Role detail: remove a member', () => {
  it('asks first and names the member and the role', async () => {
    csrfFetch.mockResolvedValue(new Response(null, { status: 204 }))
    render(<RoleDetailSheet role={role} open onOpenChange={vi.fn()} />)
    await userEvent.click(screen.getByRole('tab', { name: /Members/ }))
    await userEvent.click(screen.getByRole('button', { name: /Actions for Lan Tran/ }))
    await userEvent.click(await screen.findByRole('menuitem', { name: /Remove from role/ }))
    expect(csrfFetch).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Remove Lan Tran from the role Analyst?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove' }))
    await waitFor(() =>
      expect(csrfFetch).toHaveBeenCalledWith('/api/v1/users/u1/roles/r1', { method: 'DELETE' })
    )
  })

  // A team role is the member's role: it changes through the membership
  // (PATCH), never through /users/{id}/roles.
  it('changes a team role through the membership, not the roles API', async () => {
    csrfFetch.mockReset()
    csrfFetch.mockResolvedValue(new Response(null, { status: 200 }))
    const admin = { ...role, name: 'Admin', slug: 'admin', is_system: true } as unknown as Role
    render(<RoleDetailSheet role={admin} open onOpenChange={vi.fn()} />)
    await userEvent.click(screen.getByRole('tab', { name: /Members/ }))
    expect(screen.queryByRole('button', { name: /Add member/ })).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: /Actions for Lan Tran/ }))
    await userEvent.click(await screen.findByRole('menuitem', { name: /Change to Member/ }))
    const dialog = await screen.findByRole('alertdialog')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Change' }))
    await waitFor(() =>
      expect(csrfFetch).toHaveBeenCalledWith('/api/v1/tenants/acme/members/mem1', {
        method: 'PATCH',
        body: JSON.stringify({ role: 'member' }),
      })
    )
    expect(csrfFetch).not.toHaveBeenCalledWith(
      expect.stringContaining('/users/'),
      expect.anything()
    )
  })

  it('offers no way to remove the owner role', async () => {
    const owner = { ...role, name: 'Owner', slug: 'owner', is_system: true } as unknown as Role
    render(<RoleDetailSheet role={owner} open onOpenChange={vi.fn()} />)
    await userEvent.click(screen.getByRole('tab', { name: /Members/ }))
    expect(screen.queryByRole('button', { name: /Add member/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Actions for Lan Tran/ })).toBeNull()
  })
})
