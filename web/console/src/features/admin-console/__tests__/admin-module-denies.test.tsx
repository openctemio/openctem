import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { AdminTenantModulesResponse } from '@/lib/api/generated'
import { deleteModuleDeny, putModuleDeny, useTenantModuleEntitlements } from '../api/use-limits'
import { OrganizationModulesPanel } from '../components/organization-modules-panel'

vi.mock('../api/use-limits', async (orig) => ({
  ...(await orig<typeof import('../api/use-limits')>()),
  useTenantModuleEntitlements: vi.fn(),
  putModuleDeny: vi.fn(),
  deleteModuleDeny: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const MODULES: AdminTenantModulesResponse = {
  modules: [
    { module: 'findings', name: 'Findings', core: true, entitled: true, state: 'core' },
    {
      module: 'pentest',
      name: 'Penetration Testing',
      core: false,
      entitled: true,
      state: 'available',
    },
    {
      module: 'compliance',
      name: 'Compliance',
      core: false,
      entitled: false,
      state: 'denied',
      origin: 'operator',
      reason: 'Contract scope',
    },
    {
      module: 'workflows',
      name: 'Automations',
      core: false,
      entitled: false,
      state: 'denied',
      origin: 'control_plane',
      reason: 'service tier',
    },
  ],
}

function mockModules(data: AdminTenantModulesResponse) {
  vi.mocked(useTenantModuleEntitlements).mockReturnValue({
    data,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  } as unknown as ReturnType<typeof useTenantModuleEntitlements>)
}

describe('OrganizationModulesPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockModules(MODULES)
  })

  it('lists the non-core modules with their state and no plan wording', () => {
    render(<OrganizationModulesPanel tenantId="t1" canManage />)
    expect(screen.queryByText('Findings')).not.toBeInTheDocument()
    expect(screen.getByText('Available')).toBeInTheDocument()
    expect(screen.getAllByText('Denied')).toHaveLength(2)
    expect(screen.getByText('Contract scope')).toBeInTheDocument()
    expect(screen.queryByText(/plan/i)).not.toBeInTheDocument()
  })

  it('a deny set by the service operator has no action here', () => {
    render(<OrganizationModulesPanel tenantId="t1" canManage />)
    expect(screen.getByText('Set by the service operator')).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Allow Automations again' })
    ).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Allow Compliance again' })).toBeInTheDocument()
  })

  it('denies a module with a reason and an authenticator code', async () => {
    vi.mocked(putModuleDeny).mockResolvedValue(MODULES)
    render(<OrganizationModulesPanel tenantId="t1" canManage />)

    await userEvent.click(screen.getByRole('button', { name: 'Deny' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/only read this module for 30 days/)).toBeInTheDocument()
    const deny = within(dialog).getByRole('button', { name: 'Deny' })
    expect(deny).toBeDisabled() // a reason and a code are required
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'Contract ended')
    expect(deny).toBeDisabled()
    await userEvent.type(within(dialog).getByLabelText('Code from your authenticator'), '123456')
    await userEvent.click(deny)

    await waitFor(() =>
      expect(putModuleDeny).toHaveBeenCalledWith('t1', 'pentest', {
        reason: 'Contract ended',
        totp_code: '123456',
        expires_at: undefined,
      })
    )
  })

  it('allowing a module again asks for a reason and a code', async () => {
    vi.mocked(deleteModuleDeny).mockResolvedValue(MODULES)
    render(<OrganizationModulesPanel tenantId="t1" canManage />)
    await userEvent.click(screen.getByRole('button', { name: 'Allow Compliance again' }))
    expect(deleteModuleDeny).not.toHaveBeenCalled()

    const dialog = await screen.findByRole('dialog')
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'Contract renewed in October')
    await userEvent.type(within(dialog).getByLabelText('Code from your authenticator'), '654321')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Allow again' }))
    await waitFor(() =>
      expect(deleteModuleDeny).toHaveBeenCalledWith('t1', 'compliance', {
        reason: 'Contract renewed in October',
        totp_code: '654321',
      })
    )
  })

  it('shows a module in read-only grace with its end', () => {
    mockModules({
      modules: [
        {
          module: 'pentest',
          name: 'Penetration Testing',
          core: false,
          entitled: false,
          state: 'grace',
          origin: 'operator',
          read_only_until: '2026-11-08T12:00:00Z',
        },
      ],
    })
    render(<OrganizationModulesPanel tenantId="t1" canManage />)
    expect(screen.getByText('Read-only')).toBeInTheDocument()
    expect(
      screen.getByText(`until ${new Date('2026-11-08T12:00:00Z').toLocaleDateString()}`)
    ).toBeInTheDocument()
  })

  it('a read-only administrator sees no actions', () => {
    render(<OrganizationModulesPanel tenantId="t1" canManage={false} />)
    expect(screen.queryByRole('button', { name: 'Deny' })).not.toBeInTheDocument()
    expect(screen.getByText(/needs an operations admin/i)).toBeInTheDocument()
  })
})
