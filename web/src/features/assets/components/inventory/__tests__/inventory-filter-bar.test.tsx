/**
 * The inventory filter row: a chip per active filter that removes only its
 * filter, Add filter listing the facet registry (searchable), a picked facet's
 * editor applying as you tick, the `f` shortcut, and discovered values drawn
 * as text.
 */
import axe from 'axe-core'
import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { InventoryFilterBar } from '../inventory-filter-bar'
import { buildFacetGroups } from '../../../lib/inventory-facets'
import { inventoryChips } from '../../../lib/inventory-chips'
import { parseInventoryFilters, type InventoryFilters } from '../../../lib/inventory-url'
import type { AssetStatsData } from '../../../hooks/use-assets'

vi.mock('../inventory-tags-facet', () => ({ InventoryTagsFacet: () => <div>tags editor</div> }))
vi.mock('../inventory-technologies-facet', () => ({
  InventoryTechnologiesFacet: () => <div>technologies editor</div>,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= () => {}

const t = (_k: string, fallback?: string, vars?: Record<string, string | number>) =>
  (fallback ?? '').replace(/\{(\w+)\}/g, (_, k) => String(vars?.[k] ?? `{${k}}`))
const groups = buildFacetGroups({}, t, {
  labels: { subdomain: 'Subdomain', certificate: 'Certificate' },
  counts: { subdomain: 3, certificate: 1 },
})
const stats = { byCriticality: {}, byHasOwner: {} } as unknown as AssetStatsData

function setup(qs: string) {
  const filters = parseInventoryFilters(new URLSearchParams(qs))
  const onChange = vi.fn<(f: InventoryFilters) => void>()
  const chips = inventoryChips(filters, {
    groups,
    t,
    propertyLabel: (k) => k,
    formatDate: (s) => s,
  })
  const r = render(
    <InventoryFilterBar
      chips={chips}
      groups={groups}
      filters={filters}
      stats={stats}
      onChange={onChange}
      onClearAll={vi.fn()}
      resultLabel="361 assets"
    />
  )
  return { onChange, filters, ...r }
}

describe('InventoryFilterBar', () => {
  it('draws a chip per filter; removing one clears only it', () => {
    const { onChange } = setup('lens=external_surface&types=subdomain&criticalities=high')
    const chips = screen.getAllByTestId('inventory-filter-chip')
    expect(chips.map((c) => c.textContent)).toEqual(['Type is Subdomain', 'Criticality is High'])
    fireEvent.click(screen.getByRole('button', { name: 'Remove filter Type is Subdomain' }))
    const next = onChange.mock.calls[0][0]
    expect(next.types).toBeUndefined()
    expect(next.criticalities).toEqual(['high'])
    expect(next.lens).toBe('external_surface')
    expect(screen.getByRole('status')).toHaveTextContent('361 assets')
  })

  it('Add filter lists the registry, searches it, and a picked facet applies as you tick', async () => {
    const { onChange } = setup('')
    await userEvent.click(screen.getByRole('button', { name: /add filter/i }))
    const dialog = screen.getByRole('dialog', { name: 'Add filter' })
    for (const name of ['Type', 'Criticality', 'Ownership', 'Internet-facing', 'Tags']) {
      expect(within(dialog).getByRole('option', { name })).toBeInTheDocument()
    }
    await userEvent.type(within(dialog).getByRole('combobox'), 'critic')
    expect(within(dialog).queryByRole('option', { name: 'Type' })).toBeNull()
    await userEvent.click(within(dialog).getByRole('option', { name: 'Criticality' }))
    await userEvent.click(screen.getByRole('checkbox', { name: 'Critical' }))
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ criticalities: ['critical'], page: 1 })
    )
  })

  it('opens Add filter on f, but not while typing', async () => {
    setup('')
    const input = document.createElement('input')
    document.body.appendChild(input)
    fireEvent.keyDown(input, { key: 'f' })
    expect(screen.queryByRole('dialog', { name: 'Add filter' })).toBeNull()
    fireEvent.keyDown(document.body, { key: 'f' })
    expect(await screen.findByRole('dialog', { name: 'Add filter' })).toBeInTheDocument()
    input.remove()
  })

  it('draws a discovered value as text', () => {
    setup('tags=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E')
    const chip = screen.getByTestId('inventory-filter-chip')
    expect(chip.querySelector('img')).toBeNull()
    expect(chip.textContent).toContain('<img')
  })

  it('has no accessibility violations', async () => {
    const { container } = setup('criticalities=high&internet_facing=true')
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
