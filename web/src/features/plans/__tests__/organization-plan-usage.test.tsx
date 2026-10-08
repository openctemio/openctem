import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

import type { PlanSummaryResponse } from '@/lib/api/generated'
import { useOrganizationPlan } from '../api/use-organization-plan'
import { OrganizationPlanUsage } from '../components/organization-plan-usage'
import { formatLimit, usagePercent } from '../lib/plan-keys'

vi.mock('../api/use-organization-plan', async (orig) => ({
  ...(await orig<typeof import('../api/use-organization-plan')>()),
  useOrganizationPlan: vi.fn(),
}))

function mockPlan(value: Partial<ReturnType<typeof useOrganizationPlan>>) {
  vi.mocked(useOrganizationPlan).mockReturnValue({
    data: undefined,
    error: undefined,
    isLoading: false,
    isValidating: false,
    mutate: vi.fn(),
    ...value,
  } as unknown as ReturnType<typeof useOrganizationPlan>)
}

describe('plan-keys', () => {
  it('formats -1 as unlimited and computes a capped share', () => {
    expect(formatLimit(-1, 'Unlimited')).toBe('Unlimited')
    expect(formatLimit(undefined, 'Unlimited')).toBe('Unlimited')
    expect(formatLimit(0, 'Unlimited')).toBe('0')
    expect(usagePercent(7, 5)).toBe(100)
    expect(usagePercent(1, 4)).toBe(25)
    expect(usagePercent(3, -1)).toBeNull()
    expect(usagePercent(0, 0)).toBeNull()
  })
})

describe('OrganizationPlanUsage', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows the plan, usage and limits', () => {
    const data: PlanSummaryResponse = {
      plan: 'free',
      over_limit: false,
      limits: [
        { key: 'seats', limit: 5, used: 2, source: 'plan' },
        { key: 'sensors', limit: -1, used: 1, source: 'plan' },
        { key: 'free_teams_per_user', limit: 1, used: 0, source: 'plan' },
      ],
    }
    mockPlan({ data })
    render(<OrganizationPlanUsage />)
    expect(screen.getByText('Free')).toBeInTheDocument()
    expect(screen.getByText('Seats')).toBeInTheDocument()
    expect(screen.getAllByText('Unlimited').length).toBeGreaterThan(0)
    // A per-person limit is not this organization's usage.
    expect(screen.queryByText('Free organizations per person')).not.toBeInTheDocument()
    expect(screen.queryByText('Over your plan')).not.toBeInTheDocument()
  })

  it('explains an organization over its plan: nothing removed, new additions refused', () => {
    mockPlan({
      data: {
        plan: 'free',
        over_limit: true,
        limits: [{ key: 'seats', limit: 5, used: 7, source: 'plan', over_limit: true }],
      },
    })
    render(<OrganizationPlanUsage />)
    expect(screen.getByText('Over your plan')).toBeInTheDocument()
    expect(screen.getByText(/nothing was removed/i)).toBeInTheDocument()
    expect(screen.getByText('Over limit')).toBeInTheDocument()
  })

  it('shows an error with a retry', () => {
    mockPlan({ error: new Error('boom') })
    render(<OrganizationPlanUsage />)
    expect(screen.getByRole('button', { name: /retry|try again/i })).toBeInTheDocument()
  })
})
