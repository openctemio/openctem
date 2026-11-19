import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import useSWR, { SWRConfig } from 'swr'
import { I18nProvider } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import type { CreateDashboardInput, Dashboard } from '../api/dashboards.types'
import { DashboardHome } from '../components/dashboard-home'

// Two tabs open `/` together on a new organization. Both see no dashboard and
// both ask for the personal copy of the default template; names are unique per
// person, so the server makes one and answers the other with a conflict. The
// tab that lost must land on the copy the other tab made, never on "You have
// no dashboards yet".

vi.mock('@/lib/permissions', () => ({
  Permission: {
    DashboardsOrgView: 'dashboards:org:view',
    DashboardsOrgManage: 'dashboards:org:manage',
  },
  usePermissions: () => ({ can: () => false, canAny: () => false }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), info: vi.fn(), error: vi.fn() } }))

// A fake server with the unique-name rule of personal dashboards.
const server = vi.hoisted(() => ({
  rows: [] as Dashboard[],
  creates: 0,
  lists: 0,
  listFails: false,
}))

vi.mock('../api/use-dashboards-api', () => {
  const KEY = '/api/v1/me/dashboards'
  return {
    useDashboardHome: () => ({ status: 'ready', hasOrg: false, dataKey: null }),
    // The page's list read: the home response seeded an empty list; later
    // writes to the key (the copy, the re-read) show through the cache.
    useMyDashboards: () => {
      const { data } = useSWR<{ data: Dashboard[] }>(KEY, null, {
        fallbackData: { data: [] },
      })
      return { data, isLoading: false }
    },
    useOrgDashboards: () => ({ data: undefined, isLoading: false }),
    useRevalidateAllDashboards: () => async () => {},
    DASHBOARDS_KEY: KEY,
    createDashboard: async (input: CreateDashboardInput) => {
      server.creates++
      await Promise.resolve()
      if (server.rows.some((r) => r.name === input.name)) {
        throw new ApiClientError('you already have a dashboard with this name', 'CONFLICT', 409)
      }
      const d: Dashboard = {
        id: `d${server.creates}`,
        name: input.name,
        is_default: false,
        layout: input.layout ?? [],
        columns: input.columns ?? 4,
      }
      server.rows.push(d)
      return d
    },
    fetchMyDashboards: async () => {
      server.lists++
      if (server.listFails) throw new Error('offline')
      return { data: [...server.rows] }
    },
    addFlowPanel: vi.fn(() => Promise.reject(new Error('n/a'))),
    undoFlowPanel: vi.fn(),
    updateDashboard: vi.fn(),
    setDefaultDashboard: vi.fn(),
    setOrgDefaultDashboard: vi.fn(),
    setDashboardSchedule: vi.fn(() => Promise.resolve()),
    duplicateOrgDashboard: vi.fn(),
    deleteDashboard: vi.fn(),
  }
})

vi.mock('../api/widget-data', () => ({
  dashboardDataKey: (kind: string, id: string) => `${kind}:${id}`,
  refreshDashboard: vi.fn(),
  useDashboardData: () => ({
    data: undefined,
    isLoading: false,
    error: undefined,
    mutate: vi.fn(),
  }),
}))

// Each tab has its own cache, as two browser tabs do.
function Tab({ name }: { name: string }) {
  return (
    <section aria-label={name}>
      <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
        <I18nProvider locale="en">
          <DashboardHome />
        </I18nProvider>
      </SWRConfig>
    </section>
  )
}

describe('DashboardHome: first visit in two tabs at once', () => {
  beforeEach(() => {
    window.localStorage.clear()
    server.rows = []
    server.creates = 0
    server.lists = 0
    server.listFails = false
  })

  it('the tab whose copy was refused lands on the copy the other tab made', async () => {
    render(
      <>
        <Tab name="first" />
        <Tab name="second" />
      </>
    )
    await waitFor(() => expect(server.creates).toBe(2))
    // One copy exists on the server; both tabs show it.
    expect(server.rows).toHaveLength(1)
    await waitFor(() => expect(screen.getAllByRole('heading', { name: 'CTEM' })).toHaveLength(2))
    expect(screen.queryByText('You have no dashboards yet.')).not.toBeInTheDocument()
    // The tab that lost asked for the list once; the winner did not.
    expect(server.lists).toBe(1)
  })

  it('a refused copy with nothing on the server still shows the empty state, once', async () => {
    server.rows = []
    server.listFails = true
    // The name is taken by a dashboard the list read cannot return (it fails).
    server.rows.push({ id: 'x', name: 'CTEM', is_default: false, layout: [], columns: 4 })
    render(<Tab name="only" />)
    expect(await screen.findByText('You have no dashboards yet.')).toBeInTheDocument()
    expect(server.creates).toBe(1)
    expect(server.lists).toBe(1)
  })
})
