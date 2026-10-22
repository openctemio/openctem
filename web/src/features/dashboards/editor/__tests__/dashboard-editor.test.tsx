import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { Dashboard } from '../../api/dashboards.types'
import type { CatalogMetric, WidgetCatalog } from '../../api/widget-spec'
import { DashboardEditor } from '../dashboard-editor'

const api = vi.hoisted(() => ({
  update: vi.fn(() => Promise.resolve({})),
  updateOrg: vi.fn(() => Promise.resolve({})),
}))
vi.mock('../../api/use-dashboards-api', () => ({
  updateDashboard: api.update,
  updateOrgDashboard: api.updateOrg,
}))
const preview = vi.hoisted(() => vi.fn())
vi.mock('../../api/widget-data', () => ({ previewWidget: preview }))

const metric = (id: string, shape: 'scalar' | 'items', vizzes: string[]): CatalogMetric =>
  ({
    id,
    group: 'exposure',
    filters: ['severity'],
    group_bys: shape === 'scalar' ? ['severity'] : [],
    max_group_by: shape === 'scalar' ? 1 : 0,
    default_group_by: [],
    default_filter: {},
    polarity: 'lower_better',
    timed: false,
    flow: false,
    shapes:
      shape === 'scalar'
        ? { '0': { shape, vizzes }, '1': { shape: 'category', vizzes: ['bar', 'table'] } }
        : { '0': { shape, vizzes } },
  }) as CatalogMetric
const catalog: WidgetCatalog = {
  spec_version: 2,
  metrics: [
    metric('findings.open', 'scalar', ['stat', 'progress']),
    metric('fix.next', 'items', ['list', 'table']),
  ],
  dimensions: { severity: ['critical', 'high'] },
  time_ranges: ['inherit', '30d'],
  time_buckets: ['auto'],
  comparisons: ['none', 'previous_period'],
  target_ops: ['<=', '>='],
}
vi.mock('../../api/widget-spec', async (orig) => ({
  ...(await orig<typeof import('../../api/widget-spec')>()),
  useWidgetCatalog: () => ({ data: catalog, isLoading: false, error: undefined }),
}))
vi.mock('sonner', () => ({ toast: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }) }))

const stat = (id: string, metricId: string) => ({
  widget_type: 'metric',
  x: 0,
  y: 0,
  w: 3,
  h: 1,
  config: {
    v: 2,
    id,
    data: { kind: 'metric', metric: metricId, filter: {}, time: {} },
    viz: { type: 'stat', options: {} },
  },
})
const dashboard: Dashboard = {
  id: 'd1',
  name: 'Mine',
  is_default: true,
  columns: 4,
  layout: [stat('w_a', 'findings.open'), stat('w_b', 'intel.kev_open')],
}
const savedLayout = () =>
  (
    api.update.mock.calls.at(-1) as unknown as [
      string,
      { layout: Array<{ w: number; config: { id: string } }> },
    ]
  )[1].layout

describe('DashboardEditor', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    preview.mockResolvedValue({
      id: 'x',
      index: 0,
      widget_type: 'metric',
      state: 'ready',
      shape: 'scalar',
      scalar: { value: 4 },
    })
  })

  it('moves, resizes, removes and undoes with the keyboard only, announcing each change, then saves', async () => {
    const onExit = vi.fn()
    render(<DashboardEditor dashboard={dashboard} kind="personal" onExit={onExit} />)
    const cards = screen.getAllByTestId('editor-card')
    expect(cards[0]).toHaveAccessibleName('Open findings, position 1 of 2')
    act(() => cards[0].focus())
    fireEvent.keyDown(cards[0], { key: 'ArrowRight' })
    expect(screen.getByTestId('editor-announcer')).toHaveTextContent(
      'Open findings: position 2 of 2'
    )
    // Focus followed the moved widget.
    await waitFor(() =>
      expect(document.activeElement).toHaveAccessibleName('Open findings, position 2 of 2')
    )
    fireEvent.keyDown(document.activeElement!, { key: 'ArrowRight', shiftKey: true })
    expect(screen.getByTestId('editor-announcer')).toHaveTextContent(
      'Open findings: 2 of 4 columns wide'
    )
    fireEvent.keyDown(document.activeElement!, { key: 'Delete' })
    expect(screen.getAllByTestId('editor-card')).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Undo' }))
    expect(screen.getAllByTestId('editor-card')).toHaveLength(2)
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(api.update).toHaveBeenCalledWith('d1', expect.anything()))
    expect(savedLayout().map((w) => w.config.id)).toEqual(['w_b', 'w_a'])
    expect(savedLayout()[1].w).toBe(6)
    expect(savedLayout().some((w) => 'uid' in w)).toBe(false)
    expect(onExit).toHaveBeenCalledWith(true)
  })

  it('Ctrl+Z and Ctrl+Shift+Z undo and redo; Save is off without changes', () => {
    render(<DashboardEditor dashboard={dashboard} kind="personal" onExit={() => {}} />)
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    const card = screen.getAllByTestId('editor-card')[0]
    fireEvent.keyDown(card, { key: 'd' })
    expect(screen.getAllByTestId('editor-card')).toHaveLength(3)
    fireEvent.keyDown(window, { key: 'z', ctrlKey: true })
    expect(screen.getAllByTestId('editor-card')).toHaveLength(2)
    fireEvent.keyDown(window, { key: 'z', ctrlKey: true, shiftKey: true })
    expect(screen.getAllByTestId('editor-card')).toHaveLength(3)
  })

  it('adds from the gallery with a live preview, configures it, and saves an organization dashboard through its own route', async () => {
    render(<DashboardEditor dashboard={dashboard} kind="organization" onExit={() => {}} />)
    await userEvent.click(screen.getByRole('button', { name: 'Add widget' }))
    const card = await screen.findByTestId('gallery-card-fix.next')
    await waitFor(() => expect(preview).toHaveBeenCalled())
    await userEvent.click(within(card).getByRole('button', { name: 'Add Fix next' }))
    // The config panel opens on the new widget; a list offers only list visualizations.
    const panel = await screen.findByRole('dialog', { name: 'Configure widget' })
    expect(within(panel).getByRole('radio', { name: /List/ })).toHaveAttribute(
      'aria-checked',
      'true'
    )
    expect(within(panel).queryByRole('radio', { name: /Number/ })).toBeNull()
    expect(within(panel).queryByLabelText('Range')).toBeNull()
    await userEvent.click(within(panel).getByRole('radio', { name: 'Table' }))
    await userEvent.click(within(panel).getByRole('button', { name: 'Apply' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(api.updateOrg).toHaveBeenCalled())
    const layout = (
      api.updateOrg.mock.calls[0] as unknown as [
        string,
        {
          layout: Array<{
            widget_type: string
            config: { data: { metric: string }; viz: { type: string } }
          }>
        },
      ]
    )[1].layout
    expect(layout).toHaveLength(3)
    expect(layout[2].config.data.metric).toBe('fix.next')
    expect(layout[2].config.viz.type).toBe('table')
    expect(api.update).not.toHaveBeenCalled()
  })
})
