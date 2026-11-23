import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const update = vi.fn().mockResolvedValue({})
const remove = vi.fn().mockResolvedValue({})
const base = {
  tenant_id: 't',
  description: '',
  critical_days: 1,
  high_days: 7,
  medium_days: 30,
  low_days: 90,
  info_days: 0,
  p0_days: 1,
  p1_days: 3,
  p2_days: 10,
  p3_days: 20,
  warning_threshold_pct: 80,
  escalation_enabled: true,
  is_active: true,
  created_at: '',
  updated_at: '',
}
let policies: Array<Record<string, unknown>> = []
const seeded = [
  { ...base, id: 'd', name: 'Current', is_default: true },
  { ...base, id: 'o', name: 'Other', is_default: false, description: 'For production' },
  { ...base, id: 'a', name: 'Payments', is_default: false, asset_id: 'asset-1' },
]
policies = seeded

let allowed = new Set<string>()
const dialogPolicy = vi.fn()

vi.mock('@/features/sla/api/use-sla-policies-api', () => ({
  useSlaPoliciesApi: () => ({
    data: { data: policies, total: policies.length },
    isLoading: false,
    mutate: vi.fn(),
  }),
  useDeleteSlaPolicy: () => ({ trigger: remove, isMutating: false }),
  useUpdateSlaPolicy: () => ({ trigger: update, isMutating: false }),
  invalidateSlaPoliciesCache: vi.fn(),
}))
vi.mock('@/features/sla/components/sla-policy-dialog', () => ({
  SlaPolicyDialog: ({ open, policy }: { open: boolean; policy: { name: string } | null }) => {
    dialogPolicy(open, policy?.name ?? null)
    return open ? <div role="dialog">{policy ? `Edit ${policy.name}` : 'New'}</div> : null
  },
}))
vi.mock('@/features/sla/components/sla-windows', () => ({ SlaWindows: () => null }))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children, route }: { children: React.ReactNode; route: string }) =>
    allowed.has(route) ? children : null,
  useCanMutate: (route: string) => allowed.has(route),
  usePermissions: () => ({ can: () => true, isRole: () => true }),
  useCanRoute: () => (route: string) => allowed.has(route),
}))
vi.mock('@/features/shared/components/data-table-row-actions', async (orig) => {
  const mod = await orig<typeof import('@/features/shared/components/data-table-row-actions')>()
  return {
    ...mod,
    DataTableRowActions: ({
      actions,
      label,
    }: {
      actions: { label: string; onClick: () => void; disabled?: boolean; route?: string }[]
      label: string
    }) => (
      <div role="group" aria-label={label}>
        {actions
          .filter((a) => !a.route || allowed.has(a.route))
          .map((a) => (
            <button key={a.label} disabled={a.disabled} onClick={a.onClick}>
              {a.label}
            </button>
          ))}
      </div>
    ),
  }
})

import SlaPoliciesPage from '../page'

const WRITER = [
  'POST /api/v1/sla-policies',
  'PUT /api/v1/sla-policies/{id}',
  'DELETE /api/v1/sla-policies/{id}',
]
const row = (name: string) => screen.getAllByRole('group', { name: `Actions for ${name}` })[0]

describe('SLA policies page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    allowed = new Set(WRITER)
    window.history.replaceState(null, '', '/settings/sla-policies')
  })

  it('disables delete on the default policy only', () => {
    render(<SlaPoliciesPage />)
    expect(within(row('Current')).getByRole('button', { name: 'Delete' })).toBeDisabled()
    expect(within(row('Other')).getByRole('button', { name: 'Delete' })).toBeEnabled()
  })

  it('offers Make default only on a policy that could become the default', () => {
    render(<SlaPoliciesPage />)
    expect(within(row('Current')).queryByRole('button', { name: 'Make default' })).toBeNull()
    expect(within(row('Payments')).queryByRole('button', { name: 'Make default' })).toBeNull()
    expect(within(row('Other')).getByRole('button', { name: 'Make default' })).toBeEnabled()
  })

  it('make default asks first, names the way back, then sends is_default', async () => {
    render(<SlaPoliciesPage />)
    await userEvent.click(within(row('Other')).getByRole('button', { name: 'Make default' }))
    expect(update).not.toHaveBeenCalled()
    const dialog = screen.getByRole('alertdialog')
    expect(dialog).toHaveTextContent(/never moved later/)
    expect(dialog).toHaveTextContent('To go back, make "Current" the default again.')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Make default' }))
    expect(update).toHaveBeenCalledWith({ id: 'o', is_default: true })
  })

  it('says an asset override stops applying to its asset when deleted', async () => {
    render(<SlaPoliciesPage />)
    await userEvent.click(within(row('Payments')).getByRole('button', { name: 'Delete' }))
    expect(screen.getByRole('alertdialog')).toHaveTextContent(
      "Findings on its asset follow the organization's default policy again."
    )
  })

  it('marks a policy that applies to no finding', () => {
    render(<SlaPoliciesPage />)
    expect(screen.getAllByText('Not applied')).toHaveLength(1)
  })

  it('opens the edit dialog from ?policy= for an editor', () => {
    window.history.replaceState(null, '', '/settings/sla-policies?policy=o')
    render(<SlaPoliciesPage />)
    expect(screen.getByRole('dialog')).toHaveTextContent('Edit Other')
  })

  it('draws no search box while there are no policies', () => {
    policies = []
    try {
      render(<SlaPoliciesPage />)
      expect(screen.queryAllByRole('searchbox')).toHaveLength(0)
    } finally {
      policies = seeded
    }
  })

  it('searches by name and description', async () => {
    render(<SlaPoliciesPage />)
    await userEvent.type(screen.getAllByRole('searchbox')[0], 'production')
    expect(screen.queryAllByRole('group', { name: 'Actions for Current' })).toHaveLength(0)
    expect(screen.getAllByRole('group', { name: 'Actions for Other' }).length).toBeGreaterThan(0)
  })

  it('a reader sees the windows but no way to change them', () => {
    allowed = new Set()
    window.history.replaceState(null, '', '/settings/sla-policies?policy=o')
    render(<SlaPoliciesPage />)
    expect(screen.getByText(/View only/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'New policy' })).toBeNull()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Delete' })).toBeNull()
  })
})
