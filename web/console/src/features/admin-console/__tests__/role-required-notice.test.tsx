import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const mocks = vi.hoisted(() => ({ admin: { current: null as unknown } }))
vi.mock('../components/admin-console-shell', () => ({
  useAdminOrNull: () => mocks.admin.current,
}))

import { RoleRequiredNotice } from '../components/role-required-notice'
import { ElevationRequestContext } from '../components/elevation-request'

describe('RoleRequiredNotice', () => {
  it('offers the elevation to a super admin acting read-only, instead of a dead end', async () => {
    mocks.admin.current = {
      id: '1',
      email: 'a@x.io',
      name: 'A',
      role: 'readonly',
      max_role: 'super_admin',
    }
    const request = vi.fn()
    render(
      <ElevationRequestContext.Provider value={request}>
        <RoleRequiredNotice needed="super_admin" variant="page" />
      </ElevationRequestContext.Provider>
    )
    expect(screen.getByText('Elevate to see this page')).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Elevate' }))
    expect(request).toHaveBeenCalledOnce()
  })

  it('tells a read-only administrator which role it takes, with nothing to click', () => {
    mocks.admin.current = {
      id: '2',
      email: 'r@x.io',
      name: 'R',
      role: 'readonly',
      max_role: 'readonly',
    }
    render(
      <ElevationRequestContext.Provider value={null}>
        <RoleRequiredNotice needed="ops_admin" />
      </ElevationRequestContext.Provider>
    )
    expect(screen.getByText('This needs the Operations admin role.')).toBeInTheDocument()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('an ops admin may not elevate to super admin', () => {
    mocks.admin.current = {
      id: '3',
      email: 'o@x.io',
      name: 'O',
      role: 'readonly',
      max_role: 'ops_admin',
    }
    render(
      <ElevationRequestContext.Provider value={vi.fn()}>
        <RoleRequiredNotice needed="super_admin" />
      </ElevationRequestContext.Provider>
    )
    expect(screen.getByText('This needs the Super admin role.')).toBeInTheDocument()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })
})
