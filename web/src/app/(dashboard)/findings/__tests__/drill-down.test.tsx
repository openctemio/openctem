/**
 * Drill-down from a findings group to the list (research 24 P0-1): View is a
 * push (Back returns to the groups with their filters), the other filters are
 * kept, a breadcrumb is rebuilt from the URL, and the drilled chip's X removes
 * only its own parameter.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, screen, fireEvent, waitFor } from '@testing-library/react'

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
    data: { data: [], total: 0, page: 1, per_page: 20 },
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

import FindingsPage from '../page'

function openAt(search: string) {
  window.history.replaceState(null, '', `/findings${search}`)
}
const params = () => new URLSearchParams(window.location.search)

beforeEach(() => {
  routerPush.mockReset()
})

describe('Findings drill-down', () => {
  it('View pushes the list with both filters, and Back returns to the groups', async () => {
    openAt('?severity=critical&group=rule_id')
    const before = window.history.length
    render(<FindingsPage />)

    act(() => {
      fireEvent.click(
        screen.getByRole('button', { name: 'View the findings of ICMP Timestamp Request' })
      )
    })
    expect(params().get('severity')).toBe('critical')
    expect(params().get('rule_id')).toBe('10114')
    expect(params().get('from')).toBe('group:rule_id')
    expect(params().has('group')).toBe(false)
    // A new history entry, not a replace.
    expect(window.history.length).toBe(before + 1)
    expect(routerPush).not.toHaveBeenCalled()

    // The breadcrumb is there, built from the URL.
    const crumb = await screen.findByTestId('drill-down-breadcrumb')
    expect(crumb).toHaveTextContent('By rule')
    expect(crumb).toHaveTextContent('10114')

    act(() => {
      window.history.back()
    })
    await waitFor(() => expect(params().get('group')).toBe('rule_id'))
    expect(params().get('severity')).toBe('critical')
    expect(params().has('rule_id')).toBe(false)
  })

  it('the drilled chip X removes only its param and ends the drill-down', () => {
    openAt('?severity=critical&rule_id=10114&from=group:rule_id')
    render(<FindingsPage />)
    expect(screen.getByTestId('drill-down-breadcrumb')).toBeInTheDocument()

    act(() => {
      fireEvent.click(screen.getByRole('button', { name: 'Remove rule filter: 10114' }))
    })
    expect(params().get('severity')).toBe('critical')
    expect(params().has('rule_id')).toBe(false)
    expect(params().has('from')).toBe(false)
    expect(screen.queryByTestId('drill-down-breadcrumb')).toBeNull()
  })

  it('the breadcrumb goes back to the grouped view with the same filters', () => {
    openAt('?severity=critical&family=General&from=group:family')
    render(<FindingsPage />)
    act(() => {
      fireEvent.click(screen.getByRole('button', { name: 'By family' }))
    })
    expect(params().get('group')).toBe('family')
    expect(params().get('severity')).toBe('critical')
    expect(params().has('family')).toBe(false)
  })

  it('shows a chip for every drill-down dimension, the value as plain text', () => {
    const hostile = 'Gen\u202eeral<script>'
    openAt(
      `?family=${encodeURIComponent(hostile)}&finding_type=secret&component_id=019feab9-1111-7222-8333-444455556666&asset_owner_id_null=true`
    )
    render(<FindingsPage />)
    expect(screen.getByTestId('context-chip-family-label').textContent).not.toContain('\u202e')
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByTestId('context-chip-finding_type-label')).toHaveTextContent('secret')
    expect(screen.getByTestId('context-chip-component_id-label')).toHaveTextContent(
      'log4j-core 2.14.1'
    )
    expect(screen.getByTestId('context-chip-asset_owner_id_null-label')).toHaveTextContent(
      'Unassigned'
    )
  })
})
