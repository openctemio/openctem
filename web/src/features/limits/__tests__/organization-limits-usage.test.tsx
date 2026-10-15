import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

import type { OrganizationLimitsResponse } from '@/lib/api/generated'
import { useOrganizationLimits } from '../api/use-organization-limits'
import { OrganizationLimitsUsage } from '../components/organization-limits-usage'

vi.mock('../api/use-organization-limits', () => ({ useOrganizationLimits: vi.fn() }))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ modules: [{ id: 'pentest', name: 'Penetration Testing' }] }),
}))

function mockLimits(data: OrganizationLimitsResponse) {
  vi.mocked(useOrganizationLimits).mockReturnValue({
    data,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  } as unknown as ReturnType<typeof useOrganizationLimits>)
}

describe('OrganizationLimitsUsage', () => {
  beforeEach(() => vi.clearAllMocks())

  it('says nothing applies when the organization has no limits (the default)', () => {
    mockLimits({ applies: false, over_limit: false, limits: [], denied_features: [] })
    render(<OrganizationLimitsUsage />)
    expect(screen.getByText('No limits apply')).toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('lists the limits that apply, flags one over its limit, and names unavailable modules', () => {
    mockLimits({
      applies: true,
      over_limit: true,
      limits: [{ key: 'seats', limit: 5, used: 7, over_limit: true }],
      denied_features: [
        { feature: 'pentest', read_only_until: '2026-11-08T12:00:00Z' },
        { feature: 'threat_intel' },
      ],
    })
    render(<OrganizationLimitsUsage />)
    expect(screen.getByText('Seats')).toBeInTheDocument()
    expect(screen.getByText('Over a limit')).toBeInTheDocument()
    expect(screen.getByText(/Nothing was removed/)).toBeInTheDocument()
    expect(screen.getByText('Penetration Testing')).toBeInTheDocument()
    expect(screen.getByText('Threat intel')).toBeInTheDocument()
    expect(screen.getByText(/Read-only until/)).toBeInTheDocument()
  })

  it('uses neutral wording: no plan, tier or upgrade', () => {
    mockLimits({
      applies: true,
      over_limit: false,
      limits: [{ key: 'assets', limit: 500, used: 20 }],
      denied_features: [],
    })
    const { container } = render(<OrganizationLimitsUsage />)
    expect(container.textContent).not.toMatch(/\bplan\b|upgrade|enterprise|\bpro\b|free/i)
  })
})
