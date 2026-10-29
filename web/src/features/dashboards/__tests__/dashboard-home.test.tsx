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
  orgError: undefined as Error | undefined,
  create: vi.fn(),
  update: vi.fn(),
  addFlow: vi.fn(),
  undoFlow: vi.fn(),
}))
vi.mock('../api/use-dashboards-api', () => ({
  useMyDashboards: () => ({ data: { data: api.mine }, isLoading: false }),
  useOrgDashboards: (enabled: boolean) => {
    api.orgEnabled.push(enabled)
    if (enabled && api.orgError) return { data: undefined, error: api.orgError, isLoading: false }
    return { data: enabled ? { data: api.org } : undefined, isLoading: false }
  },
  useRevalidateAllDashboards: () => async () => {},
  DASHBOARDS_KEY: '/api/v1/me/dashboards',
  createDashboard: api.create,
  addFlowPanel: api.addFlow,
  undoFlowPanel: api.undoFlow,
  updateDashboard: api.update,
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
      <DashboardHome />
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
    api.orgError = undefined
    data.byKey = {}
    vi.clearAllMocks()
  })

  it('a person with no dashboard at all gets a personal copy of the CTEM template, once', async () => {
    api.create.mockResolvedValue({ id: 'new1' })
    const { rerender } = renderHome()
    await waitFor(() => expect(api.create).toHaveBeenCalledTimes(1))
    const input = api.create.mock.calls[0][0] as {
      name: string
      columns: number
      layout: Array<{ widget_type: string }>
    }
    expect(input.name).toBe('CTEM')
    expect(input.columns).toBe(4)
    expect(input.layout.length).toBeGreaterThan(4)
    expect(input.layout.every((w) => w.widget_type === 'metric')).toBe(true)
    const metrics = input.layout.map(
      (w) => (w as unknown as { config: { data: { metric: string } } }).config.data.metric
    )
    // The CTEM story leads: the levers, the exposure flow (with the five
    // stages) and the key figures, then the brief, fix next and attack paths.
    expect(metrics.slice(0, 3)).toEqual(['exposure.levers', 'exposure.flow', 'exposure.kpis'])
    expect(metrics).toContain('brief.weekly')
    expect(metrics).toContain('ingest.intake')
    expect(metrics).toContain('fix.next')
    expect(metrics).toContain('attack_paths.to_crown_jewels')
    rerender(
      <I18nProvider locale="en">
        <DashboardHome />
      </I18nProvider>
    )
    expect(api.create).toHaveBeenCalledTimes(1)
    expect(window.localStorage.getItem(DASHBOARD_CHOICE_KEY)).toBe('personal:new1')
  })

  it('no copy when the organization has dashboards for the viewer; a failed copy shows the empty state', async () => {
    perms.list = ['dashboards:org:view']
    api.org = [dash('o1', 'Overview', { is_org_default: true })]
    renderHome()
    expect(api.create).not.toHaveBeenCalled()
  })

  it('no copy when the organization list failed to load', async () => {
    perms.list = ['dashboards:org:view']
    api.orgError = new Error('boom')
    renderHome()
    await new Promise((r) => setTimeout(r, 0))
    expect(api.create).not.toHaveBeenCalled()
  })

  it('a failed copy leaves a way to create one', async () => {
    api.create.mockRejectedValue(new Error('no'))
    renderHome()
    expect(await screen.findByText('You have no dashboards yet.')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'New dashboard' })).toHaveAttribute(
      'href',
      '/dashboards'
    )
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

  it('Customize is offered on an organization dashboard to a manager only', () => {
    perms.list = ['dashboards:org:view', 'dashboards:org:manage']
    api.org = [dash('o2', 'Overview', { is_org_default: true })]
    data.byKey['organization:o2'] = snapshot('organization', 1)
    renderHome()
    expect(screen.getByRole('button', { name: 'Customize' })).toBeInTheDocument()
  })

  it('Edit details is hidden on an organization dashboard for a viewer, shown to a manager', async () => {
    perms.list = ['dashboards:org:view']
    api.org = [dash('o2', 'Overview', { is_org_default: true })]
    data.byKey['organization:o2'] = snapshot('organization', 1)
    const { unmount } = renderHome()
    await userEvent.click(screen.getByRole('button', { name: 'More dashboard actions' }))
    expect(screen.queryByRole('menuitem', { name: 'Edit details' })).toBeNull()
    unmount()
    perms.list = ['dashboards:org:view', 'dashboards:org:manage']
    renderHome()
    await userEvent.click(screen.getByRole('button', { name: 'More dashboard actions' }))
    expect(screen.getByRole('menuitem', { name: 'Edit details' })).toBeInTheDocument()
  })

  it('Refresh now stays enabled when the figures failed to load', () => {
    api.mine = [dash('p1', 'Mine', { is_default: true })]
    renderHome()
    expect(screen.getByRole('button', { name: 'Refresh now' })).toBeEnabled()
  })

  it('the personal delete confirm does not claim the dashboard is deleted for everyone', async () => {
    api.mine = [dash('p1', 'Mine', { is_default: true })]
    data.byKey['personal:p1'] = snapshot('personal', 5)
    renderHome()
    await userEvent.click(screen.getByRole('button', { name: 'More dashboard actions' }))
    await userEvent.click(screen.getByRole('menuitem', { name: 'Delete' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent(
      'Copies you shared and the data behind the widgets are not affected'
    )
    expect(dialog).not.toHaveTextContent('for everyone')
  })

  it('setting a default clears the stored last choice and shows no success toast', async () => {
    api.mine = [dash('p1', 'Mine', { is_default: true }), dash('p2', 'Other')]
    data.byKey['personal:p2'] = snapshot('personal', 5)
    window.localStorage.setItem(DASHBOARD_CHOICE_KEY, 'personal:p2')
    renderHome()
    await userEvent.click(screen.getByRole('button', { name: 'More dashboard actions' }))
    await userEvent.click(screen.getByRole('menuitem', { name: 'Set as my default' }))
    const { setDefaultDashboard } = await import('../api/use-dashboards-api')
    await waitFor(() => expect(setDefaultDashboard).toHaveBeenCalledWith('p2'))
    await waitFor(() => expect(window.localStorage.getItem(DASHBOARD_CHOICE_KEY)).toBeNull())
    expect(toast.success).not.toHaveBeenCalled()
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
    // The Updated line already shows the change: no success toast.
    expect(toast.success).not.toHaveBeenCalled()
    data.refresh.mockRejectedValueOnce(new ApiClientError('limited', 'TOO_MANY_REQUESTS', 429))
    await userEvent.click(screen.getByRole('button', { name: 'Refresh now' }))
    await waitFor(() => expect(toast.info).toHaveBeenCalled())
  })

  it('the actions menu carries Customize and the schedule for the phone toolbar', async () => {
    api.mine = [dash('p1', 'Mine', { is_default: true })]
    data.byKey['personal:p1'] = snapshot('personal', 5)
    renderHome()
    // One toolbar row: the switcher, Refresh (named even when icon-only) and More.
    const toolbar = screen.getByTestId('dashboard-toolbar')
    expect(within(toolbar).getByRole('button', { name: /Switch dashboard/ })).toBeInTheDocument()
    expect(within(toolbar).getByRole('button', { name: 'Refresh now' })).toBeInTheDocument()
    await userEvent.click(within(toolbar).getByRole('button', { name: 'More dashboard actions' }))
    const menu = screen.getByRole('menu')
    expect(within(menu).getByRole('menuitem', { name: 'Customize' })).toBeInTheDocument()
    const radios = within(menu).getAllByRole('menuitemradio')
    expect(radios.map((r) => r.textContent)).toContain('Organization default')
    await userEvent.click(within(menu).getByRole('menuitemradio', { name: 'Every 6 hours' }))
    const { setDashboardSchedule } = await import('../api/use-dashboards-api')
    await waitFor(() => expect(setDashboardSchedule).toHaveBeenCalledWith('personal', 'p1', '6h'))
  })

  it('the meta line names the scope, the last and the next refresh on one line', () => {
    api.mine = [dash('p1', 'Mine', { is_default: true })]
    data.byKey['personal:p1'] = snapshot('personal', 5)
    renderHome()
    const meta = screen.getByTestId('dashboard-meta')
    expect(meta).toHaveTextContent('Your scope')
    expect(meta).toHaveTextContent(/Updated/)
  })

  it('renders in Vietnamese', () => {
    api.mine = [dash('p1', 'Mine', { is_default: true })]
    data.byKey['personal:p1'] = snapshot('personal', 5)
    renderHome('vi')
    expect(screen.getByText('Phạm vi của bạn')).toBeInTheDocument()
    expect(screen.getByText('Phát hiện đang mở')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Làm mới ngay' })).toBeInTheDocument()
  })
})

describe('DashboardHome new layout hint', () => {
  const overviewCopy = (id: string): Dashboard =>
    dash(id, 'Overview', {
      kind: 'personal',
      columns: 4,
      layout: [
        stat('w_ov1', 'exposure.priority_open'),
        stat('w_ov2', 'intel.kev_open'),
        stat('w_ov3', 'sla.within'),
        { ...stat('w_ov5', 'exposure.open_by_priority'), h: 2 },
        { ...stat('w_ov8', 'sla.at_risk'), h: 3 },
      ],
    })

  beforeEach(() => {
    window.localStorage.clear()
    perms.list = []
    api.mine = []
    api.org = []
    api.orgError = undefined
    data.byKey = {}
    vi.clearAllMocks()
  })

  it('offers the new widgets on an earlier Overview copy and never changes it on its own', async () => {
    api.mine = [overviewCopy('d1')]
    renderHome()
    const hint = await screen.findByTestId('layout-hint')
    expect(hint).toHaveTextContent('New on the Overview layout: What would cut exposure most')
    expect(within(hint).getByRole('button', { name: 'Add them to this dashboard' })).toBeVisible()
    expect(within(hint).getByRole('button', { name: 'Switch to the new layout' })).toBeVisible()
    expect(api.update).not.toHaveBeenCalled()
    expect(api.create).not.toHaveBeenCalled()
  })

  it('"Add them" inserts each missing widget where the template has it and keeps every widget', async () => {
    api.mine = [overviewCopy('d1')]
    api.update.mockResolvedValue({})
    renderHome()
    await userEvent.click(await screen.findByRole('button', { name: 'Add them to this dashboard' }))
    await waitFor(() => expect(api.update).toHaveBeenCalledTimes(1))
    const [id, input] = api.update.mock.calls[0] as [
      string,
      { name: string; layout: Array<{ config: { id: string; data: { metric: string } } }> },
    ]
    expect(id).toBe('d1')
    expect(input.name).toBe('Overview')
    expect(input.layout.map((w) => w.config.data.metric)).toEqual([
      // The copy's own figures keep their place.
      'exposure.priority_open',
      'intel.kev_open',
      'sla.within',
      'exposure.levers',
      'exposure.flow',
      'exposure.kpis',
      'brief.weekly',
      'attack_paths.to_crown_jewels',
      'exposure.open_by_priority',
      'flow.new_vs_fixed',
      'findings.age_bands',
      'fix.next',
      // The person's own extra widget stays.
      'sla.at_risk',
    ])
    expect(new Set(input.layout.map((w) => w.config.id)).size).toBe(input.layout.length)
    expect(screen.queryByTestId('layout-hint')).toBeNull()
  })

  it('"Switch to the new layout" adds a fresh copy and keeps the old dashboard', async () => {
    api.mine = [overviewCopy('d1')]
    api.create.mockResolvedValue({ id: 'c1' })
    renderHome()
    await userEvent.click(await screen.findByRole('button', { name: 'Switch to the new layout' }))
    await waitFor(() => expect(api.create).toHaveBeenCalledTimes(1))
    // The copy the hint is on already uses the template's name.
    expect((api.create.mock.calls[0][0] as { name: string }).name).toBe('Overview (new layout)')
    expect(api.update).not.toHaveBeenCalled()
    expect(window.localStorage.getItem(DASHBOARD_CHOICE_KEY)).toBe('personal:c1')
  })

  it('the fresh copy never takes a name the person already uses', async () => {
    api.mine = [{ ...overviewCopy('d1'), name: 'Overview' }, dash('d2', 'Overview (new layout)')]
    window.localStorage.setItem(DASHBOARD_CHOICE_KEY, 'personal:d1')
    api.create.mockResolvedValue({ id: 'c1' })
    renderHome()
    await userEvent.click(await screen.findByRole('button', { name: 'Switch to the new layout' }))
    await waitFor(() => expect(api.create).toHaveBeenCalledTimes(1))
    expect((api.create.mock.calls[0][0] as { name: string }).name).toBe('Overview (new layout) 2')
  })

  it('a dismissed hint stays dismissed for this layout version', async () => {
    api.mine = [overviewCopy('d1')]
    const { unmount } = renderHome()
    await userEvent.click(await screen.findByRole('button', { name: 'Dismiss' }))
    expect(screen.queryByTestId('layout-hint')).toBeNull()
    unmount()
    renderHome()
    expect(await screen.findByTestId('dashboard-freshness')).toBeInTheDocument()
    expect(screen.queryByTestId('layout-hint')).toBeNull()
    expect(api.update).not.toHaveBeenCalled()
  })

  it('no hint on a dashboard that is not a template copy, or on an organization dashboard', async () => {
    perms.list = ['dashboards:org:view', 'dashboards:org:manage']
    for (const d of [dash('d2', 'Mine', { kind: 'personal' })]) {
      api.mine = [d]
      const { unmount } = renderHome()
      expect(await screen.findByTestId('dashboard-freshness')).toBeInTheDocument()
      expect(screen.queryByTestId('layout-hint')).toBeNull()
      unmount()
    }
    api.mine = []
    api.org = [{ ...overviewCopy('o1'), kind: 'organization', is_org_default: true }]
    data.byKey['organization:o1'] = snapshot('organization', 1)
    renderHome()
    expect(await screen.findByTestId('dashboard-freshness')).toBeInTheDocument()
    expect(screen.queryByTestId('layout-hint')).toBeNull()
  })
})

describe('DashboardHome exposure flow panel', () => {
  const eligible = (id: string, extra: Partial<Dashboard> = {}): Dashboard =>
    dash(id, 'Mine', { kind: 'personal', is_default: true, flow_panel_at: null, ...extra })
  const flowWidget = {
    ...stat('w_flow', 'exposure.flow'),
    config: {
      v: 2,
      id: 'w_flow',
      data: { kind: 'metric', metric: 'exposure.flow', filter: {}, time: {} },
      viz: { type: 'flow', options: {} },
    },
  }

  beforeEach(() => {
    window.localStorage.clear()
    perms.list = []
    api.mine = []
    api.org = []
    api.orgError = undefined
    data.byKey = {}
    vi.clearAllMocks()
    api.addFlow.mockResolvedValue({ added: true, widget_id: 'w_flow', dashboard: eligible('d1') })
    api.undoFlow.mockResolvedValue(eligible('d1'))
  })

  it('adds the panel once to an eligible personal dashboard and offers Undo', async () => {
    api.mine = [eligible('d1')]
    const view = renderHome()
    await waitFor(() => expect(api.addFlow).toHaveBeenCalledTimes(1))
    expect(api.addFlow).toHaveBeenCalledWith('d1', 'personal')
    await waitFor(() => expect(toast.success).toHaveBeenCalled())
    const [message, opts] = toast.success.mock.calls[0] as [
      string,
      { action: { label: string; onClick: () => void } },
    ]
    expect(message).toBe('Exposure flow added at the top')
    expect(opts.action.label).toBe('Undo')
    // Re-rendering never asks again.
    view.rerender(
      <I18nProvider locale="en">
        <DashboardHome />
      </I18nProvider>
    )
    expect(api.addFlow).toHaveBeenCalledTimes(1)
    // No layout hint on the open that added the panel.
    expect(screen.queryByTestId('layout-hint')).toBeNull()

    opts.action.onClick()
    await waitFor(() => expect(api.undoFlow).toHaveBeenCalledWith('d1', 'personal', 'w_flow'))
  })

  it('does nothing when flow_panel_at is set, the layout already has the flow or is empty', async () => {
    api.mine = [
      eligible('d1', { flow_panel_at: '2026-10-01T00:00:00Z' }),
      eligible('d2', { is_default: false, layout: [flowWidget] }),
      eligible('d3', { is_default: false, layout: [] }),
    ]
    renderHome()
    await screen.findByRole('heading', { name: 'Mine' })
    expect(api.addFlow).not.toHaveBeenCalled()
    // An older server without the field is not "never offered".
    api.mine = [dash('d4', 'Old', { kind: 'personal', is_default: true })]
    renderHome()
    expect(api.addFlow).not.toHaveBeenCalled()
  })

  it('never touches an organization dashboard the person cannot manage', async () => {
    perms.list = ['dashboards:org:view']
    api.org = [eligible('o1', { kind: 'organization', is_org_default: true, is_default: false })]
    renderHome()
    await screen.findByRole('heading', { name: 'Mine' })
    expect(api.addFlow).not.toHaveBeenCalled()
  })

  it('offers an organization dashboard to a manager once', async () => {
    perms.list = ['dashboards:org:view', 'dashboards:org:manage']
    api.org = [eligible('o1', { kind: 'organization', is_org_default: true, is_default: false })]
    renderHome()
    await waitFor(() => expect(api.addFlow).toHaveBeenCalledWith('o1', 'organization'))
    expect(api.addFlow).toHaveBeenCalledTimes(1)
  })

  it('shows no toast when the panel was already offered elsewhere', async () => {
    api.addFlow.mockResolvedValue({ added: false, dashboard: eligible('d1') })
    api.mine = [eligible('d1')]
    renderHome()
    await waitFor(() => expect(api.addFlow).toHaveBeenCalledTimes(1))
    expect(toast.success).not.toHaveBeenCalled()
  })
})
