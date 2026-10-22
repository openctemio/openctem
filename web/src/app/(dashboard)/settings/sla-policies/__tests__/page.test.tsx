import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const update = vi.fn().mockResolvedValue({})
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
const policies = [
  { ...base, id: 'd', name: 'Current', is_default: true },
  { ...base, id: 'o', name: 'Other', is_default: false },
]

vi.mock('@/features/sla/api/use-sla-policies-api', () => ({
  useSlaPoliciesApi: () => ({
    data: { data: policies, total: 2 },
    isLoading: false,
    mutate: vi.fn(),
  }),
  useDeleteSlaPolicy: () => ({ trigger: vi.fn(), isMutating: false }),
  useUpdateSlaPolicy: () => ({ trigger: update, isMutating: false }),
  invalidateSlaPoliciesCache: vi.fn(),
}))
vi.mock('@/features/sla/components/sla-policy-dialog', () => ({ SlaPolicyDialog: () => null }))
vi.mock('@/features/sla/components/sla-windows', () => ({ SlaWindows: () => null }))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => children,
  Permission: { SLAWrite: 'w', SLADelete: 'd' },
}))

import SlaPoliciesPage from '../page'

describe('SLA policies page', () => {
  it('disables delete on the default policy only', () => {
    render(<SlaPoliciesPage />)
    expect(screen.getByRole('button', { name: 'Delete Current' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Delete Other' })).toBeEnabled()
  })

  it('make default needs a confirmation before sending is_default', async () => {
    render(<SlaPoliciesPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Make Other the default' }))
    expect(update).not.toHaveBeenCalled()
    expect(screen.getByText(/never moved later/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Make default' }))
    expect(update).toHaveBeenCalledWith({ id: 'o', is_default: true })
  })
})
