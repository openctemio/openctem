import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

import { ScopingOverview } from '../components/scoping-overview'

let granted = new Set<string>()
let summary: unknown
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useHasPermission: (p: string) => granted.has(p),
  useNavItemAccess: () => () => true,
}))
vi.mock('../api', () => ({
  useScopingSummary: () => ({
    data: summary,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
}))

const base = {
  active_cycle: null,
  crown_jewels: { total: 0, with_owner: 0 },
  business_services: { total: 0, with_assets: 0 },
  business_units: { total: 0 },
  assets: { total: 0, in_business_unit: 0 },
  boundary: { targets: 0, targets_waiting: 0, exclusions: 0 },
  attacker_profiles: { total: 0 },
  threat_models: { total: 0, crown_jewels_covered: 0 },
  cycles: { total: 0 },
}
const cycle = {
  id: 'c1',
  name: 'Q4',
  status: 'active',
  start_date: null,
  end_date: null,
  objectives: 0,
  success_criteria: 0,
  in_scope_services: 0,
  exclusions: 0,
  threat_scenarios: 0,
  scope_assets: 0,
  attacker_profiles: 0,
}

describe('scoping overview: Start a cycle', () => {
  beforeEach(() => {
    granted = new Set()
    summary = base
  })

  it('is hidden without ctem:cycles:write', () => {
    render(<ScopingOverview />)
    expect(screen.queryByRole('link', { name: /start a cycle/i })).toBeNull()
  })

  it('is shown with ctem:cycles:write', () => {
    granted = new Set(['ctem:cycles:write'])
    render(<ScopingOverview />)
    expect(screen.getByRole('link', { name: /start a cycle/i })).toBeInTheDocument()
  })

  it('keeps Open cycle for readers when a cycle is running', () => {
    summary = { ...base, active_cycle: cycle }
    render(<ScopingOverview />)
    expect(screen.getByRole('link', { name: /open cycle/i })).toBeInTheDocument()
  })
})
