/**
 * The inventory's Query mode (the search field's Basic | Query switch, wired
 * as the page wires it): chips and text are two views of one filter. The text shown is what POST /query/parse prints for the page's list
 * params; a submitted text comes back as page filters when chips can show it,
 * and as one Advanced chip (fq) when they cannot.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import type { ParseResult } from '@/features/query/api/query-api'
import { ListSearch } from '@/features/shared/components/list-search'
import { useListQueryMode } from '@/features/query/components/query-mode'
import { InventoryFilterBar } from '../inventory-filter-bar'
import { applyTextResult, textParams } from '../../../lib/inventory-text'
import { buildFacetGroups } from '../../../lib/inventory-facets'
import { inventoryChips } from '../../../lib/inventory-chips'
import { parseInventoryFilters, type InventoryFilters } from '../../../lib/inventory-url'
import type { AssetStatsData } from '../../../hooks/use-assets'

const api = vi.hoisted(() => ({ parse: vi.fn() }))
vi.mock('@/features/query/api/query-api', () => ({
  queryApi: { parse: api.parse },
  useQuerySchema: () => ({ data: { fields: [] } }),
}))
vi.mock('@/features/query/components/query-input', () => ({
  QueryInput: (p: {
    value: string
    onChange: (v: string) => void
    onSubmit?: (r: ParseResult) => void
    disabled?: boolean
    preferFields?: string[]
  }) => (
    <div>
      <input
        aria-label="query"
        value={p.value}
        disabled={p.disabled}
        data-prefer={(p.preferFields ?? []).join(',')}
        onChange={(e) => p.onChange(e.target.value)}
      />
      <button
        onClick={() =>
          p.onSubmit?.({
            entity: 'assets',
            valid: true,
            text: p.value,
            query: '',
            chips: [],
            advanced: p.value.includes(' OR '),
            problems: [],
            params: p.value.includes(' OR ') ? undefined : { port_gte: '1', criticality: 'high' },
          })
        }
      >
        run
      </button>
    </div>
  ),
}))
vi.mock('../inventory-tags-facet', () => ({ InventoryTagsFacet: () => <div /> }))
vi.mock('../inventory-technologies-facet', () => ({ InventoryTechnologiesFacet: () => <div /> }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const t = (_k: string, fb?: string, vars?: Record<string, string | number>) =>
  (fb ?? '').replace(/\{(\w+)\}/g, (_, k) => String(vars?.[k] ?? `{${k}}`))
const groups = buildFacetGroups({}, t)
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
  function Harness() {
    // As the page: the mode is part of the filters' URL (`mode=query`).
    const [active, setActive] = useState(!!filters.queryMode)
    const mode = useListQueryMode({
      entity: 'assets',
      active,
      onActiveChange: setActive,
      fq: filters.advanced ?? null,
      params: textParams(filters),
      onApply: (r, on) => {
        onChange({ ...applyTextResult(filters, r), page: 1, queryMode: on || undefined })
        setActive(on)
      },
      preferFields: ['ip', 'network'],
      testId: 'inventory-query-editor',
    })
    return (
      <>
        <ListSearch value="" onChange={() => undefined} placeholder="Search" query={mode.query} />
        <InventoryFilterBar
          chips={chips}
          filters={filters}
          onChange={onChange}
          onClearAll={vi.fn()}
          queryActive={mode.active}
          onOpenQuery={() => mode.setActive(true)}
        />
      </>
    )
  }
  render(<Harness />)
  return { onChange }
}

describe('InventoryFilterBar and the Query mode', () => {
  beforeEach(() => api.parse.mockReset())

  it('shows the page filter as text, printed by the server from the list params only', async () => {
    api.parse.mockResolvedValue({ valid: true, text: 'criticality:high network=198.51.100.0/24' })
    setup('lens=external_surface&tab=ip_address&criticalities=high&network=198.51.100.0/24&page=2')
    fireEvent.click(screen.getByRole('button', { name: 'Query' }))
    await waitFor(() =>
      expect(screen.getByLabelText('query')).toHaveValue('criticality:high network=198.51.100.0/24')
    )
    // The tab is a locked condition: not in the text. Paging is not either.
    expect(api.parse).toHaveBeenCalledWith({
      entity: 'assets',
      params: 'criticality=high&network=198.51.100.0%2F24',
    })
    // The open tab's fields are completed first.
    expect(screen.getByLabelText('query')).toHaveAttribute('data-prefer', 'ip,network')
  })

  it('a text chips can show comes back as page filters, tab kept', async () => {
    api.parse.mockResolvedValue({ valid: true, text: '' })
    const { onChange } = setup('lens=external_surface&tab=ip_address')
    fireEvent.click(screen.getByRole('button', { name: 'Query' }))
    await waitFor(() => expect(screen.getByLabelText('query')).not.toBeDisabled())
    fireEvent.change(screen.getByLabelText('query'), {
      target: { value: 'port>=1 criticality:high' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'run' }))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({
        lens: 'external_surface',
        tab: 'ip_address',
        criticalities: ['high'],
        extra: { port_gte: '1' },
        page: 1,
      })
    )
    expect(onChange.mock.calls[0][0].advanced).toBeUndefined()
    // Enter keeps Query mode, in the URL.
    expect(onChange.mock.calls[0][0].queryMode).toBe(true)
  })

  it('a text chips cannot show is kept whole as one Advanced chip that removes alone', async () => {
    api.parse.mockResolvedValue({ valid: true, text: '' })
    const { onChange } = setup('criticalities=high')
    fireEvent.click(screen.getByRole('button', { name: 'Query' }))
    await waitFor(() => expect(screen.getByLabelText('query')).not.toBeDisabled())
    fireEvent.change(screen.getByLabelText('query'), { target: { value: 'port=22 OR port=23' } })
    fireEvent.click(screen.getByRole('button', { name: 'run' }))
    const next = onChange.mock.calls[0][0]
    expect(next.advanced).toBe('port=22 OR port=23')
    expect(next.criticalities).toBeUndefined()
  })

  it('Query mode owns the filter: the chips step aside', async () => {
    api.parse.mockResolvedValue({ valid: true, text: 'criticality:high' })
    setup('criticalities=high')
    expect(screen.getByTestId('inventory-filter-chip')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Query' }))
    await waitFor(() => expect(screen.getByLabelText('query')).toHaveValue('criticality:high'))
    expect(screen.queryByTestId('inventory-filter-chip')).toBeNull()
  })

  it('the Advanced chip opens Query mode with its text', async () => {
    api.parse.mockResolvedValue({ valid: true, text: '' })
    setup('fq=port%3D22+OR+port%3D23&lens=data')
    fireEvent.click(screen.getByText('port=22 OR port=23'))
    await waitFor(() => expect(screen.getByLabelText('query')).toHaveValue('port=22 OR port=23'))
  })

  it('a link in Query mode opens with the text in the field, no Advanced chip', async () => {
    api.parse.mockResolvedValue({ valid: true, text: 'port=22 OR port=23' })
    setup('fq=port%3D22+OR+port%3D23&lens=data&mode=query')
    await waitFor(() => expect(screen.getByLabelText('query')).toHaveValue('port=22 OR port=23'))
    expect(screen.queryByTestId('filter-chip-advanced')).toBeNull()
  })

  it('draws an fq filter as one Advanced chip, removable', () => {
    const { onChange } = setup('fq=port%3D22+OR+port%3D23&lens=data')
    expect(screen.getByTestId('filter-chip-advanced')).toHaveTextContent('port=22 OR port=23')
    fireEvent.click(screen.getByRole('button', { name: 'Remove the advanced filter' }))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ advanced: undefined, lens: 'data', page: 1 })
    )
  })
})
