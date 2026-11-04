import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'

const replace = vi.fn()
let search = ''
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace }),
  usePathname: () => '/emerging-threats/et-1',
  useSearchParams: () => new URLSearchParams(search),
}))
const toastSuccess = vi.fn()
vi.mock('sonner', () => ({ toast: { success: (m: string) => toastSuccess(m), error: vi.fn() } }))

type Org = { id: string; name: string; slug: string }
const CURRENT: Org = { id: 'org-current', name: 'Current Org', slug: 'current' }
const OTHER: Org = { id: 'org-other', name: 'Other Org', slug: 'other' }

const tenantState = {
  currentTenant: { ...CURRENT, role: 'member' } as (Org & { role: string }) | null,
  tenants: [] as Org[],
  error: null as Error | null,
  switchTeam: vi.fn(async (_id: string) => {}),
  loadTenants: vi.fn(),
}
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => tenantState }))

import { OrgLinkGate } from '../org-link-gate'

function page() {
  return render(
    <OrgLinkGate>
      <p>threat detail</p>
    </OrgLinkGate>
  )
}

beforeEach(() => {
  replace.mockReset()
  toastSuccess.mockReset()
  tenantState.switchTeam.mockReset()
  tenantState.switchTeam.mockImplementation(async () => {})
  tenantState.loadTenants.mockReset()
  tenantState.currentTenant = { ...CURRENT, role: 'member' }
  tenantState.tenants = [CURRENT, OTHER]
  tenantState.error = null
  search = ''
})

describe('OrgLinkGate', () => {
  it('renders the page directly without an org parameter', () => {
    page()
    expect(screen.getByText('threat detail')).toBeInTheDocument()
    expect(tenantState.switchTeam).not.toHaveBeenCalled()
    expect(replace).not.toHaveBeenCalled()
  })

  it('switches to another organization of the person first, then shows the page', async () => {
    search = `org=${OTHER.id}&tab=assets`
    let resolveSwitch: () => void = () => {}
    tenantState.switchTeam.mockImplementation(() => new Promise<void>((r) => (resolveSwitch = r)))
    page()
    // The page must not load (and ask the wrong organization) before the switch.
    expect(screen.queryByText('threat detail')).not.toBeInTheDocument()
    expect(screen.getByTestId('org-link-gate')).toBeInTheDocument()
    expect(tenantState.switchTeam).toHaveBeenCalledWith(OTHER.id)

    resolveSwitch()
    await waitFor(() => expect(screen.getByText('threat detail')).toBeInTheDocument())
    expect(toastSuccess).toHaveBeenCalledWith('Switched to Other Org')
    // The parameter is dropped from the address; the rest is kept.
    expect(replace).toHaveBeenCalledWith('/emerging-threats/et-1?tab=assets', { scroll: false })
  })

  it('accepts the organization slug too', async () => {
    search = 'org=other'
    page()
    await waitFor(() => expect(screen.getByText('threat detail')).toBeInTheDocument())
    expect(tenantState.switchTeam).toHaveBeenCalledWith(OTHER.id)
  })

  it('does not switch when the link names the selected organization', async () => {
    search = `org=${CURRENT.id}`
    page()
    await waitFor(() => expect(screen.getByText('threat detail')).toBeInTheDocument())
    expect(tenantState.switchTeam).not.toHaveBeenCalled()
    expect(replace).toHaveBeenCalledWith('/emerging-threats/et-1', { scroll: false })
  })

  it.each([
    ['an organization the person does not belong to', 'org-not-mine'],
    ['an unknown organization', 'no-such-org'],
  ])('renders the page in the selected organization for %s (same not-found)', async (_c, org) => {
    search = `org=${org}`
    page()
    await waitFor(() => expect(screen.getByText('threat detail')).toBeInTheDocument())
    // No switch attempt, no message that would tell the cases apart.
    expect(tenantState.switchTeam).not.toHaveBeenCalled()
    expect(toastSuccess).not.toHaveBeenCalled()
    expect(replace).toHaveBeenCalledWith('/emerging-threats/et-1', { scroll: false })
  })

  it('waits for the membership list before deciding', async () => {
    search = `org=${OTHER.id}`
    tenantState.tenants = []
    const { rerender } = page()
    expect(tenantState.loadTenants).toHaveBeenCalled()
    expect(tenantState.switchTeam).not.toHaveBeenCalled()
    expect(screen.queryByText('threat detail')).not.toBeInTheDocument()

    tenantState.tenants = [CURRENT, OTHER]
    rerender(
      <OrgLinkGate>
        <p>threat detail</p>
      </OrgLinkGate>
    )
    await waitFor(() => expect(screen.getByText('threat detail')).toBeInTheDocument())
    expect(tenantState.switchTeam).toHaveBeenCalledWith(OTHER.id)
  })

  it('still renders the page (uniform not-found) when the switch is refused', async () => {
    search = `org=${OTHER.id}`
    tenantState.switchTeam.mockRejectedValue(new Error('forbidden'))
    page()
    await waitFor(() => expect(screen.getByText('threat detail')).toBeInTheDocument())
    expect(toastSuccess).not.toHaveBeenCalled()
  })
})
