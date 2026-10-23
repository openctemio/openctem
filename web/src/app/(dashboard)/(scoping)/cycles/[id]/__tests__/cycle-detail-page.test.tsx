import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import CycleDetailPage from '../page'

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'c1' }),
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/cycles/c1',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/features/cycles/api', () => ({
  useCycle: () => ({
    data: {
      id: 'c1',
      name: 'Q4',
      status: 'active',
      start_date: '2026-10-01',
      end_date: '2026-12-31',
      charter: {},
    },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useCycleScope: () => ({ data: undefined, error: new Error('scope failed') }),
  useCycleProfiles: () => ({ data: undefined, error: new Error('profiles failed') }),
}))
vi.mock('@/features/cycles', () => ({
  CharterEditorSheet: () => null,
  summarizeEvaluation: () => null,
}))
vi.mock('@/features/cycles/components/cycle-status-badge', () => ({ CycleStatusBadge: () => null }))
vi.mock('@/features/cycles/components/cycle-lifecycle-actions', () => ({
  CycleLifecycleAction: () => null,
}))
vi.mock('@/features/cycles/components/cycle-detail-tabs', () => ({
  CycleCharterTab: () => null,
  CycleOutcomeTab: () => null,
  CycleProfilesTab: () => null,
  CycleScopeTab: () => null,
}))

describe('cycle detail strip', () => {
  it('shows a dash and a hint, not an endless ellipsis, when scope and profile reads fail', () => {
    render(<CycleDetailPage />)
    expect(screen.getByText('Scope could not be loaded.')).toBeInTheDocument()
    expect(screen.getByText('Attacker profiles could not be loaded.')).toBeInTheDocument()
    expect(screen.queryByText('…')).toBeNull()
  })
})
