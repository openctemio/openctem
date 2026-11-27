import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => '/assets/r1',
}))

vi.mock('@/features/repositories', async (orig) => {
  const actual = await orig<typeof import('@/features/repositories')>()
  return {
    ...actual,
    useRepository: () => ({
      data: {
        id: 'r1',
        name: 'gitlab.example.com/group/app',
        type: 'repository',
        criticality: 'medium',
        status: 'active',
        scope: 'internal',
        exposure: 'private',
        risk_score: 0,
        finding_count: 203,
        first_seen: '2026-01-01T00:00:00Z',
        last_seen: '2026-01-01T00:00:00Z',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        repository: {
          asset_id: 'r1',
          full_name: 'gitlab.example.com/group/app',
          web_url: 'https://gitlab.example.com/group/app',
        },
      },
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    }),
    useRepositoryBranches: () => ({ data: [], isLoading: false }),
  }
})

// One page of 20 loaded, 203 in total.
vi.mock('@/features/findings/api/use-findings-api', () => ({
  useFindingsApi: () => ({
    data: { data: Array.from({ length: 20 }, () => ({})), total: 203, total_pages: 11 },
    isLoading: false,
  }),
}))

vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => false,
}))

vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    usePermissions: () => ({ can: () => true }),
    Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  }
})

import { RepositoryWorkspace } from './repository-workspace'

describe('RepositoryWorkspace', () => {
  it('counts the Findings tab by the total, not the loaded page', () => {
    render(<RepositoryWorkspace repositoryId="r1" />)
    const tab = screen.getByRole('tab', { name: /Findings/ })
    expect(tab.textContent).toContain('203')
    expect(tab.textContent).not.toMatch(/\b20\b(?!\d)/)
  })

  it('names the host provider for a repository with no stored provider', () => {
    render(<RepositoryWorkspace repositoryId="r1" />)
    expect(screen.getAllByText('GitLab').length).toBeGreaterThan(0)
    expect(screen.queryByText('GitHub')).toBeNull()
  })
})
