import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { CatalogMetric } from '../../api/widget-spec'
import { PREVIEWS_PER_OPEN, WidgetGallery } from '../widget-gallery'

const preview = vi.hoisted(() => vi.fn())
vi.mock('../../api/widget-data', () => ({ previewWidget: preview }))
const many = Array.from(
  { length: PREVIEWS_PER_OPEN + 5 },
  (_, i) =>
    ({
      id: i === 0 ? 'findings.open' : `m.x${i}`,
      group: i === 0 ? 'exposure' : 'remediation',
      filters: [],
      group_bys: [],
      max_group_by: 0,
      default_group_by: [],
      default_filter: {},
      polarity: 'neutral',
      timed: false,
      flow: false,
      shapes: { '0': { shape: 'scalar', vizzes: ['stat'] } },
    }) as CatalogMetric
)
vi.mock('../../api/widget-spec', async (orig) => ({
  ...(await orig<typeof import('../../api/widget-spec')>()),
  useWidgetCatalog: () => ({
    data: {
      spec_version: 2,
      metrics: many,
      dimensions: {},
      time_ranges: [],
      time_buckets: [],
      comparisons: [],
      target_ops: [],
    },
    isLoading: false,
  }),
}))

describe('WidgetGallery', () => {
  it('loads at most PREVIEWS_PER_OPEN live previews per opening, filters by group and search', async () => {
    preview.mockResolvedValue({
      id: 'x',
      index: 0,
      widget_type: 'metric',
      state: 'ready',
      shape: 'scalar',
      scalar: { value: 1 },
    })
    render(
      <WidgetGallery
        open
        onOpenChange={() => {}}
        taken={new Set()}
        onAddMetric={() => {}}
        onAddNote={() => {}}
      />
    )
    await waitFor(() => expect(preview).toHaveBeenCalledTimes(PREVIEWS_PER_OPEN))
    expect(screen.getAllByText('Add it to see your figures.')).toHaveLength(5)
    await userEvent.click(screen.getByRole('tab', { name: 'Exposure' }))
    expect(screen.getAllByTestId(/^gallery-card-/)).toHaveLength(1)
    await userEvent.click(screen.getByRole('tab', { name: 'All' }))
    await userEvent.type(screen.getByRole('textbox', { name: 'Search widgets' }), 'open findings')
    expect(screen.getAllByTestId(/^gallery-card-/)).toHaveLength(1)
    expect(preview).toHaveBeenCalledTimes(PREVIEWS_PER_OPEN)
  })

  it('has one-row group tabs with a roving tabindex, and a shrinkable single-column card list', async () => {
    preview.mockResolvedValue(undefined)
    render(
      <WidgetGallery
        open
        onOpenChange={() => {}}
        taken={new Set()}
        onAddMetric={() => {}}
        onAddNote={() => {}}
      />
    )
    const tabs = screen.getAllByRole('tab')
    expect(tabs).toHaveLength(6)
    expect(screen.queryByRole('tab', { name: 'Advanced' })).toBeNull()
    expect(tabs.filter((t) => t.getAttribute('tabindex') !== '-1').length).toBeLessThanOrEqual(1)
    expect(screen.getByRole('tablist').className).toContain('overflow-x-auto')
    expect(screen.getByRole('tablist').className).not.toContain('flex-wrap')
    // A wide preview must not stretch the list past the sheet.
    const card = screen.getAllByTestId(/^gallery-card-/)[0]
    expect(card.className).toContain('min-w-0')
    expect(card.parentElement?.className).toContain('grid-cols-[minmax(0,1fr)]')
    await userEvent.click(tabs[0])
    await userEvent.keyboard('{ArrowRight}')
    expect(tabs[1]).toHaveFocus()
  })

  it('does not request a loaded preview again when a tab is switched back', async () => {
    preview.mockReset()
    preview.mockResolvedValue({
      id: 'x',
      index: 0,
      widget_type: 'metric',
      state: 'ready',
      shape: 'scalar',
      scalar: { value: 1 },
    })
    render(
      <WidgetGallery
        open
        onOpenChange={() => {}}
        taken={new Set()}
        onAddMetric={() => {}}
        onAddNote={() => {}}
      />
    )
    await waitFor(() => expect(preview).toHaveBeenCalledTimes(PREVIEWS_PER_OPEN))
    await userEvent.click(screen.getByRole('tab', { name: 'Exposure' }))
    await screen.findByTestId('gallery-card-findings.open')
    await userEvent.click(screen.getByRole('tab', { name: 'All' }))
    await userEvent.click(screen.getByRole('tab', { name: 'Remediation and SLA' }))
    await userEvent.click(screen.getByRole('tab', { name: 'All' }))
    expect(preview).toHaveBeenCalledTimes(PREVIEWS_PER_OPEN)
    expect(screen.getAllByText('Add it to see your figures.')).toHaveLength(5)
  })

  it('draws the preview without a nested bordered frame, and keeps the note card in All', async () => {
    preview.mockReset()
    preview.mockResolvedValue({
      id: 'x',
      index: 0,
      widget_type: 'metric',
      state: 'ready',
      shape: 'scalar',
      scalar: { value: 1 },
    })
    render(
      <WidgetGallery
        open
        onOpenChange={() => {}}
        taken={new Set()}
        onAddMetric={() => {}}
        onAddNote={() => {}}
      />
    )
    await waitFor(() => expect(preview).toHaveBeenCalled())
    const card = screen.getByTestId('gallery-card-findings.open')
    await waitFor(() => expect(card.querySelector('[class*="pointer-events-none"]')).not.toBeNull())
    await waitFor(() => expect(preview).toHaveBeenCalledTimes(PREVIEWS_PER_OPEN))
    expect(card.querySelectorAll('[class*="border"]').length).toBe(
      card.className.includes('border') ? 1 : 0
    )
    expect(screen.getByText('Text for context, links or instructions.')).toBeInTheDocument()
  })
})
