/**
 * Bulk "Resolved" closes every selected finding: it asks first and states the
 * count; one click on the menu item changes nothing.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const csrfFetch = vi.hoisted(() => vi.fn())
vi.mock('@/lib/api/client', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/client')>()),
  csrfFetch,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const routerPush = vi.fn()

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: routerPush, replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/findings',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))

vi.mock('swr', () => ({
  default: vi.fn(() => ({ data: undefined, error: undefined, isLoading: false, mutate: vi.fn() })),
  mutate: vi.fn(),
  useSWRConfig: () => ({ mutate: vi.fn() }),
}))

vi.mock('@/features/findings/api/use-findings-api', () => ({
  useFindingsApi: () => ({
    data: {
      data: [
        {
          id: 'f1',
          title: 'Outdated TLS',
          severity: 'high',
          status: 'confirmed',
          created_at: '2026-10-01T00:00:00Z',
          updated_at: '2026-10-01T00:00:00Z',
        },
        {
          id: 'f2',
          title: 'Open admin panel',
          severity: 'critical',
          status: 'confirmed',
          created_at: '2026-10-01T00:00:00Z',
          updated_at: '2026-10-01T00:00:00Z',
        },
      ],
      total: 2,
      page: 1,
      per_page: 20,
    },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useFindingStatsApi: () => ({
    data: { total: 0, by_severity: {}, by_status: {}, open_count: 0 },
    isLoading: false,
    mutate: vi.fn(),
  }),
  buildFindingsExportUrl: () => '#',
  buildFindingsEndpoint: () => '/api/v1/findings',
  fetchFindings: vi.fn(),
  invalidateFindingsCache: vi.fn(),
}))

vi.mock('@/features/findings/api/use-finding-groups', async (orig) => ({
  ...(await orig<typeof import('@/features/findings/api/use-finding-groups')>()),
  useFindingGroups: () => ({
    data: {
      data: [
        {
          group_key: '10114',
          group_type: 'rule',
          label: 'ICMP Timestamp Request',
          severity: 'low',
          metadata: {},
          stats: {
            total: 3,
            open: 3,
            in_progress: 0,
            fix_applied: 0,
            resolved: 0,
            affected_assets: 3,
          },
        },
      ],
      pagination: { total: 1, page: 1, per_page: 20 },
    },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
}))

vi.mock('@/features/config/api/finding-source-api', () => ({
  useFindingSourcesApi: () => ({ data: undefined }),
  groupFindingSourcesByCategory: () => [],
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => true,
}))
vi.mock('@/features/saved-views/components/saved-views-menu', () => ({
  SavedViewsMenu: () => null,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/features/findings/components/auto-assign-dialog', () => ({
  AutoAssignDialog: () => null,
}))
vi.mock('@/features/findings/components/mark-fixed-dialog', () => ({ MarkFixedDialog: () => null }))
vi.mock('@/features/findings/components/create-ticket-dialog', () => ({
  CreateTicketDialog: () => null,
}))
vi.mock('@/features/remediation/components/link-findings-dialog', () => ({
  LinkFindingsToRemediationDialog: () => null,
}))
vi.mock('@/features/findings', async (orig) => ({
  ...(await orig<typeof import('@/features/findings')>()),
  FindingDetailDrawer: () => null,
  CreateFindingDialog: () => null,
}))
vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAsset: () => ({ asset: null, isLoading: false, error: undefined }),
}))
vi.mock('@/features/components/api/hooks', () => ({
  useComponentVersion: () => ({
    data: { name: 'log4j-core', version: '2.14.1' },
    isLoading: false,
  }),
}))

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', slug: 't1' } }),
}))
vi.mock('@/features/findings/components/assignee-select', () => ({ AssigneeSelect: () => null }))

import FindingsPage from '../page'

describe('Findings bulk resolve', () => {
  it('asks before resolving the selected findings', async () => {
    csrfFetch.mockResolvedValue(
      new Response(JSON.stringify({ updated: 2, failed: 0 }), { status: 200 })
    )
    window.history.replaceState(null, '', '/findings')
    render(<FindingsPage />)
    await userEvent.click(screen.getAllByRole('checkbox', { name: /select all/i })[0])
    const bar = screen.getByRole('toolbar', { name: 'Actions for selected rows' })
    await userEvent.click(within(bar).getByRole('button', { name: 'Status' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Resolved' }))

    const bulkCalls = () =>
      csrfFetch.mock.calls.filter(([url]) => String(url).includes('/findings/bulk/status'))
    expect(bulkCalls()).toHaveLength(0)
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Resolve 2 findings?')

    await userEvent.click(within(dialog).getByRole('button', { name: 'Resolve' }))
    await waitFor(() => expect(bulkCalls()).toHaveLength(1))
    expect(JSON.parse(String(bulkCalls()[0][1]?.body))).toMatchObject({
      finding_ids: ['f1', 'f2'],
      status: 'resolved',
    })
  })
})
