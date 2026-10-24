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

  it('a widget header holds only the handle, the title, Configure and More; the rest is in the menu', async () => {
    render(<DashboardEditor dashboard={dashboard} kind="personal" onExit={() => {}} />)
    const chrome = screen.getAllByTestId('editor-chrome')[0]
    // The title truncates and keeps its full name on hover.
    expect(within(chrome).getByTitle('Open findings')).toHaveClass('truncate', 'min-w-0')
    expect(chrome).toHaveClass('overflow-hidden', 'min-w-0')
    // No row of move and resize buttons in the header.
    for (const name of ['Move earlier', 'Move later', 'Narrower', 'Wider', 'Shorter', 'Taller'])
      expect(within(chrome).queryByRole('button', { name })).toBeNull()
    expect(
      within(chrome).getByRole('button', { name: 'Configure Open findings' })
    ).toBeInTheDocument()
    // Duplicate and Remove show inline only on a wide widget (container query).
    expect(within(chrome).getByRole('button', { name: 'Remove Open findings' })).toHaveClass(
      'hidden',
      '@[22rem]:inline-flex'
    )
    await userEvent.click(
      within(chrome).getByRole('button', { name: 'More actions for Open findings' })
    )
    const menu = screen.getByRole('menu')
    const items = within(menu).getAllByRole('menuitem')
    expect(items.map((i) => i.textContent?.replace(/[←→↑↓⇧]|Del$|D$/g, '').trim())).toEqual([
      'Move earlier',
      'Move later',
      'Narrower',
      'Wider',
      'Shorter',
      'Taller',
      'Duplicate',
      'Remove',
    ])
    // Remove is last, after a separator, in the destructive colour.
    expect(items.at(-1)).toHaveClass('text-destructive')
    expect(items.at(-1)?.previousElementSibling).toHaveAttribute('role', 'separator')
    expect(within(menu).getByRole('menuitem', { name: /Move earlier/ })).toHaveAttribute(
      'data-disabled'
    )
    await userEvent.click(within(menu).getByRole('menuitem', { name: /Move later/ }))
    expect(screen.getAllByTestId('editor-card')[1]).toHaveAccessibleName(
      'Open findings, position 2 of 2'
    )
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

describe('DashboardEditor guards and config panel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Element.prototype.scrollIntoView = vi.fn()
    Element.prototype.hasPointerCapture = vi.fn(() => false)
    preview.mockResolvedValue({
      id: 'x',
      index: 0,
      widget_type: 'metric',
      state: 'ready',
      shape: 'scalar',
      scalar: { value: 4 },
    })
  })

  it('Cancel with unsaved changes asks before discarding; without changes it leaves at once', async () => {
    const onExit = vi.fn()
    render(<DashboardEditor dashboard={dashboard} kind="personal" onExit={onExit} />)
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onExit).toHaveBeenCalledWith(false)
    onExit.mockClear()
    const card = screen.getAllByTestId('editor-card')[0]
    act(() => card.focus())
    fireEvent.keyDown(card, { key: 'ArrowRight' })
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onExit).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Discard your changes?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Keep editing' }))
    expect(onExit).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await userEvent.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', {
        name: 'Discard changes',
      })
    )
    expect(onExit).toHaveBeenCalledWith(false)
  })

  it('guards beforeunload only while there are unsaved changes', () => {
    render(<DashboardEditor dashboard={dashboard} kind="personal" onExit={() => {}} />)
    const fire = () => {
      const e = new Event('beforeunload', { cancelable: true })
      window.dispatchEvent(e)
      return e.defaultPrevented
    }
    expect(fire()).toBe(false)
    const card = screen.getAllByTestId('editor-card')[0]
    act(() => card.focus())
    fireEvent.keyDown(card, { key: 'ArrowRight' })
    expect(fire()).toBe(true)
  })

  it('Undo in the remove toast puts the removed widget back even after another change', async () => {
    const { toast } = await import('sonner')
    render(<DashboardEditor dashboard={dashboard} kind="personal" onExit={() => {}} />)
    const cards = screen.getAllByTestId('editor-card')
    act(() => cards[0].focus())
    fireEvent.keyDown(cards[0], { key: 'Delete' })
    const toastArgs = (toast as unknown as ReturnType<typeof vi.fn>).mock.calls.at(-1) as [
      string,
      { action: { onClick: () => void } },
    ]
    // Another change after the removal: widen the remaining widget.
    const left = screen.getAllByTestId('editor-card')[0]
    act(() => left.focus())
    fireEvent.keyDown(left, { key: 'ArrowRight', shiftKey: true })
    act(() => toastArgs[1].action.onClick())
    const names = screen.getAllByTestId('editor-card').map((c) => c.getAttribute('aria-label'))
    expect(names).toHaveLength(2)
    expect(names[0]).toMatch(/^Open findings/)
    // The later widening is kept (a plain undo would have reverted it).
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(api.update).toHaveBeenCalled())
    expect(savedLayout().map((w) => w.config.id)).toEqual(['w_a', 'w_b'])
    expect(savedLayout()[1].w).toBe(6)
  })

  it('Configure on a widget with stored figures does not request a preview; a change does', async () => {
    const value = {
      id: 'v',
      index: 0,
      widget_type: 'metric',
      state: 'ready',
      shape: 'scalar',
      metric: 'findings.open',
      scalar: { value: 9 },
    }
    render(
      <DashboardEditor
        dashboard={dashboard}
        kind="personal"
        data={{ widgets: [value], computed_at: '2026-01-01T00:00:00Z' } as never}
        onExit={() => {}}
      />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Configure Open findings' }))
    const panel = await screen.findByRole('dialog', { name: 'Configure widget' })
    await act(async () => {
      await new Promise((r) => setTimeout(r, 700))
    })
    expect(preview).not.toHaveBeenCalled()
    await userEvent.click(within(panel).getByRole('radio', { name: /Progress/ }))
    await waitFor(() => expect(preview).toHaveBeenCalledTimes(1), { timeout: 2000 })
  })

  it('a target with no value disables Apply and shows the unit', async () => {
    render(<DashboardEditor dashboard={dashboard} kind="personal" onExit={() => {}} />)
    await userEvent.click(screen.getByRole('button', { name: 'Configure Open findings' }))
    const panel = await screen.findByRole('dialog', { name: 'Configure widget' })
    await userEvent.click(within(panel).getByRole('combobox', { name: 'Better when' }))
    await userEvent.click(await screen.findByRole('option', { name: 'At most' }))
    const input = within(panel).getByLabelText('Value')
    expect(within(panel).getByText('items')).toBeInTheDocument()
    await userEvent.clear(input)
    expect(within(panel).getByRole('button', { name: 'Apply' })).toBeDisabled()
    await userEvent.type(input, '5')
    expect(within(panel).getByRole('button', { name: 'Apply' })).toBeEnabled()
  })
})
