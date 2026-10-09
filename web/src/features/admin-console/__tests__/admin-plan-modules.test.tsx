import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { AdminTenantModulesResponse, PlanModulesResponse } from '@/lib/api/generated'
import {
  deleteModuleGrant,
  putModuleGrant,
  savePlanModules,
  useTenantModuleEntitlements,
} from '../api/use-plans'
import { PlanModulesForm, toPlanModules } from '../components/plan-modules-form'
import { OrganizationModulesPanel } from '../components/organization-modules-panel'

vi.mock('../api/use-plans', async (orig) => ({
  ...(await orig<typeof import('../api/use-plans')>()),
  savePlanModules: vi.fn(),
  useTenantModuleEntitlements: vi.fn(),
  putModuleGrant: vi.fn(),
  deleteModuleGrant: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const BUILTIN: PlanModulesResponse = {
  builtin: true,
  version: 0,
  plans: { free: ['*'], pro: ['*'], enterprise: ['*'] },
  modules: [
    { id: 'pentest', name: 'Penetration Testing', release: 'released' },
    { id: 'compliance', name: 'Compliance', release: 'released' },
  ],
}

describe('PlanModulesForm', () => {
  beforeEach(() => vi.clearAllMocks())

  it('starts from every module for every plan', () => {
    render(<PlanModulesForm data={BUILTIN} canEdit onSaved={vi.fn()} />)
    expect(screen.getByLabelText('Free: every module')).toBeChecked()
    expect(screen.getByLabelText('Free: Penetration Testing')).toBeDisabled()
    expect(screen.getByText(/every plan includes every module/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('narrows a plan and saves with the authenticator code', async () => {
    vi.mocked(savePlanModules).mockResolvedValue({ ...BUILTIN, version: 1 })
    const onSaved = vi.fn()
    render(<PlanModulesForm data={BUILTIN} canEdit onSaved={onSaved} />)

    // Leaving "every module" keeps every listed module, then one is removed.
    await userEvent.click(screen.getByLabelText('Free: every module'))
    await userEvent.click(screen.getByLabelText('Free: Penetration Testing'))
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    const dialog = await screen.findByRole('alertdialog')
    await userEvent.type(within(dialog).getByLabelText(/code from your authenticator/i), '123456')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Confirm' }))

    await waitFor(() =>
      expect(savePlanModules).toHaveBeenCalledWith({
        plans: { free: ['compliance'], pro: ['*'], enterprise: ['*'] },
        version: 0,
        totp_code: '123456',
      })
    )
    expect(onSaved).toHaveBeenCalled()
  })

  it('a read-only administrator cannot change them', () => {
    render(<PlanModulesForm data={BUILTIN} canEdit={false} onSaved={vi.fn()} />)
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('Free: every module')).toBeDisabled()
  })

  it('serializes "every module" as ["*"] and ids sorted', () => {
    expect(
      toPlanModules({
        free: { all: false, ids: new Set(['pentest', 'compliance']) },
        pro: { all: true, ids: new Set() },
        enterprise: { all: true, ids: new Set() },
      })
    ).toEqual({ free: ['compliance', 'pentest'], pro: ['*'], enterprise: ['*'] })
  })
})

const ENTITLEMENTS: AdminTenantModulesResponse = {
  plan: 'free',
  modules: [
    {
      module: 'findings',
      name: 'Findings',
      core: true,
      entitled: true,
      source: 'core',
      in_plan: true,
    },
    {
      module: 'pentest',
      name: 'Penetration Testing',
      core: false,
      entitled: false,
      source: 'none',
      in_plan: false,
    },
    {
      module: 'compliance',
      name: 'Compliance',
      core: false,
      entitled: true,
      source: 'plan',
      in_plan: true,
    },
    {
      module: 'workflows',
      name: 'Automations',
      core: false,
      entitled: true,
      source: 'grant',
      in_plan: false,
      grant_reason: '14-day trial',
      grant_expires_at: '2026-11-01T00:00:00Z',
    },
  ],
}

describe('OrganizationModulesPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useTenantModuleEntitlements).mockReturnValue({
      data: ENTITLEMENTS,
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    } as unknown as ReturnType<typeof useTenantModuleEntitlements>)
  })

  it('lists the non-core modules with their source', () => {
    render(<OrganizationModulesPanel tenantId="t1" canManage />)
    expect(screen.queryByText('Findings')).not.toBeInTheDocument()
    expect(screen.getByText('Not in the plan')).toBeInTheDocument()
    expect(screen.getByText('In the plan')).toBeInTheDocument()
    expect(screen.getByText('Granted')).toBeInTheDocument()
    expect(screen.getByText('14-day trial')).toBeInTheDocument()
  })

  it('grants a module with a reason', async () => {
    vi.mocked(putModuleGrant).mockResolvedValue(ENTITLEMENTS)
    render(<OrganizationModulesPanel tenantId="t1" canManage />)

    await userEvent.click(screen.getByRole('button', { name: 'Grant' }))
    const dialog = await screen.findByRole('dialog')
    const grant = within(dialog).getByRole('button', { name: 'Grant' })
    expect(grant).toBeDisabled() // a reason is required
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'trial')
    await userEvent.click(grant)

    await waitFor(() =>
      expect(putModuleGrant).toHaveBeenCalledWith('t1', 'pentest', {
        kind: 'grant',
        reason: 'trial',
        expires_at: undefined,
      })
    )
  })

  it('lets the plan decide again', async () => {
    vi.mocked(deleteModuleGrant).mockResolvedValue(ENTITLEMENTS)
    render(<OrganizationModulesPanel tenantId="t1" canManage />)
    await userEvent.click(screen.getByRole('button', { name: 'Let the plan decide Automations' }))
    await waitFor(() => expect(deleteModuleGrant).toHaveBeenCalledWith('t1', 'workflows'))
  })

  it('a read-only administrator sees no actions', () => {
    render(<OrganizationModulesPanel tenantId="t1" canManage={false} />)
    expect(screen.queryByRole('button', { name: 'Grant' })).not.toBeInTheDocument()
    expect(screen.getByText(/needs an operations admin/i)).toBeInTheDocument()
  })
})
