import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { I18nProvider } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import type { Dashboard } from '../api/dashboards.types'
import type { DashboardData } from '../api/widget-data'
import { DashboardHome } from '../components/dashboard-home'
import { DASHBOARD_CHOICE_KEY } from '../landing'

const perms = vi.hoisted(() => ({ list: [] as string[] }))
vi.mock('@/lib/permissions', () => ({
  Permission: {
    DashboardsOrgView: 'dashboards:org:view',
    DashboardsOrgManage: 'dashboards:org:manage',
  },
  usePermissions: () => ({
    can: (p: string) => perms.list.includes(p),
    canAny: (...p: string[]) => p.some((x) => perms.list.includes(x)),
  }),
}))

const toast = vi.hoisted(() => ({ success: vi.fn(), info: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const api = vi.hoisted(() => ({
  mine: [] as Dashboard[],
  org: [] as Dashboard[],
  orgEnabled: [] as boolean[],
}))
vi.mock('../api/use-dashboards-api', () => ({
  useMyDashboards: () => ({ data: { data: api.mine }, isLoading: false }),
  useOrgDashboards: (enabled: boolean) => {
    api.orgEnabled.push(enabled)
    return { data: enabled ? { data: api.org } : undefined, isLoading: false }
  },
  useRevalidateAllDashboards: () => async () => {},
  setDefaultDashboard: vi.fn(),
  setOrgDefaultDashboard: vi.fn(),
  setDashboardSchedule: vi.fn(() => Promise.resolve()),
  duplicateOrgDashboard: vi.fn(),
  deleteDashboard: vi.fn(),
}))

const data = vi.hoisted(() => ({
  byKey: {} as Record<string, unknown>,
  refresh: vi.fn(),
}))
vi.mock('../api/widget-data', () => ({
  dashboardDataKey: (kind: string, id: string) => `${kind}:${id}`,
  refreshDashboard: data.refresh,
  useDashboardData: (kind: string, id: string | null) => ({
    data: id ? data.byKey[`${kind}:${id}`] : undefined,
    isLoading: false,
    error: undefined,
    mutate: vi.fn(),
  }),
}))

const stat = (id: string, metric: string) => ({
  widget_type: 'metric',
  x: 0,
  y: 0,
  w: 6,
  h: 1,
  config: {
    v: 2,
    id,
    data: { kind: 'metric', metric, filter: {}, time: {} },
    viz: { type: 'stat', options: {} },
  },
})

const dash = (id: string, name: string, extra: Partial<Dashboard> = {}): Dashboard => ({
  id,
  name,
  is_default: false,
  layout: [stat('w_open', 'findings.open'), stat('w_kev', 'intel.kev_open')],
  columns: 2,
  ...extra,
})

const snapshot = (scope: 'personal' | 'organization', open: number): DashboardData => ({
  dashboard_id: 'x',
  scope,
  restricted: scope === 'personal',
  facts_built_at: '2026-10-21T08:00:00Z',
  computed_at: new Date().toISOString(),
  refresh_schedule: '1h',
  next_refresh_at: new Date(Date.now() + 3600_000).toISOString(),
  stale: false,
  widgets: [
    {
      id: 'w_open',
      index: 0,
      widget_type: 'metric',
      state: 'ready',
      shape: 'scalar',
      metric: 'findings.open',
      scalar: { value: open },
    },
    {
      id: 'w_kev',
      index: 1,
      widget_type: 'metric',
      state: 'ready',
      shape: 'scalar',
      metric: 'intel.kev_open',
      scalar: { value: 2 },
    },
  ],
})

function renderHome(locale: 'en' | 'vi' = 'en') {
  return render(
    <I18nProvider locale={locale}>
      <DashboardHome empty={<div>EMPTY_VIEW</div>} />
    </I18nProvider>
  )
}

describe('DashboardHome', () => {
  beforeEach(() => {
    window.localStorage.clear()
    perms.list = []
    api.mine = []
    api.org = []
    api.orgEnabled = []
    data.byKey = {}
    vi.clearAllMocks()
  })

  it('shows the empty view when the viewer has no stored dashboard', () => {
    renderHome()
    expect(screen.getByText('EMPTY_VIEW')).toBeInTheDocument()
  })

  it('opens my default dashboard from its snapshot, in my scope, and never asks for organization dashboards without the permission', async () => {
    api.mine = [dash('p1', 'Other'), dash('p2', 'Mine', { is_default: true })]
    data.byKey['personal:p2'] = snapshot('personal', 31)
    renderHome()
    expect(screen.getByRole('heading', { name: 'Mine' })).toBeInTheDocument()
    expect(screen.getByText('Your scope')).toBeInTheDocument()
    expect(screen.getByText('Open findings')).toBeInTheDocument()
    expect(screen.getByText('31')).toBeInTheDocument()
    expect(screen.getByText('KEV on your assets')).toBeInTheDocument()
    expect(api.orgEnabled.every((e) => e === false)).toBe(true)
    await userEvent.click(screen.getByRole('button', { name: /Switch dashboard/ }))
    expect(screen.queryByText('Organization')).toBeNull()
    expect(screen.getByText('Mine', { selector: '[role=menuitem] span' })).toBeInTheDocument()
    await userEvent.keyboard('{Escape}')
    // My own dashboard: Customize and the schedule picker are offered.
    expect(screen.getByRole('button', { name: 'Customize' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Refresh schedule' })).toBeInTheDocument()
  })

  it('an organization viewer lands on the organization default, badge organization-wide, no schedule or customize without manage', () => {
    perms.list = ['dashboards:org:view']
    api.mine = [dash('p1', 'Mine')]
    api.org = [dash('o1', 'Program'), dash('o2', 'Overview', { is_org_default: true })]
    data.byKey['organization:o2'] = snapshot('organization', 120)
    renderHome()
    expect(screen.getByRole('heading', { name: 'Overview' })).toBeInTheDocument()
    expect(screen.getByText('Organization-wide')).toBeInTheDocument()
    expect(screen.getByText('120')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Customize' })).toBeNull()
    expect(screen.queryByRole('combobox', { name: 'Refresh schedule' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Refresh now' })).toBeEnabled()
  })

  it('a manager may set the organization schedule', () => {
    perms.list = ['dashboards:org:view', 'dashboards:org:manage']
    api.org = [dash('o2', 'Overview', { is_org_default: true })]
    data.byKey['organization:o2'] = snapshot('organization', 1)
    renderHome()
    expect(screen.getByRole('combobox', { name: 'Refresh schedule' })).toBeInTheDocument()
  })

  it('keeps the last choice and switches from the menu', async () => {
    perms.list = ['dashboards:org:view']
    api.mine = [dash('p1', 'Mine')]
    api.org = [dash('o1', 'Program')]
    data.byKey['personal:p1'] = snapshot('personal', 5)
    data.byKey['organization:o1'] = snapshot('organization', 50)
    window.localStorage.setItem(DASHBOARD_CHOICE_KEY, 'personal:p1')
    renderHome()
    expect(screen.getByRole('heading', { name: 'Mine' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Switch dashboard/ }))
    const menu = screen.getByRole('menu')
    expect(within(menu).getByText('Organization')).toBeInTheDocument()
    await userEvent.click(within(menu).getByText('Program'))
    expect(screen.getByRole('heading', { name: 'Program' })).toBeInTheDocument()
    expect(window.localStorage.getItem(DASHBOARD_CHOICE_KEY)).toBe('organization:o1')
  })

  it('Refresh now stores the new snapshot; a 429 explains the limit', async () => {
    api.mine = [dash('p1', 'Mine', { is_default: true })]
    data.byKey['personal:p1'] = snapshot('personal', 5)
    data.refresh.mockResolvedValueOnce(snapshot('personal', 6))
    renderHome()
    await userEvent.click(screen.getByRole('button', { name: 'Refresh now' }))
    await waitFor(() => expect(data.refresh).toHaveBeenCalledWith('personal', 'p1'))
    expect(toast.success).toHaveBeenCalled()
    data.refresh.mockRejectedValueOnce(new ApiClientError('limited', 'TOO_MANY_REQUESTS', 429))
    await userEvent.click(screen.getByRole('button', { name: 'Refresh now' }))
    await waitFor(() => expect(toast.info).toHaveBeenCalled())
  })

  it('renders in Vietnamese', () => {
    api.mine = [dash('p1', 'Mine', { is_default: true })]
    data.byKey['personal:p1'] = snapshot('personal', 5)
    renderHome('vi')
    expect(screen.getByText('Phạm vi của bạn')).toBeInTheDocument()
    expect(screen.getByText('Finding đang mở')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Làm mới ngay' })).toBeInTheDocument()
  })
})
