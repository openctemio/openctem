import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import type { InventoryFilters } from '../../../lib/inventory-url'
import { countActiveFilters, parseInventoryFilters } from '../../../lib/inventory-url'

const facetsHook = vi.fn()
vi.mock('../../../hooks/use-asset-technologies', () => ({
  useTechnologyFacets: (...args: unknown[]) => facetsHook(...args),
}))

import { InventoryTechnologiesFacet } from '../inventory-technologies-facet'

function setup(filters: InventoryFilters) {
  const onChange = vi.fn()
  render(<InventoryTechnologiesFacet filters={filters} onChange={onChange} />)
  const header = screen.getByRole('button', { name: /Technologies/ })
  if (header.getAttribute('aria-expanded') === 'false') fireEvent.click(header)
  return onChange
}

beforeEach(() => {
  facetsHook.mockReset()
  facetsHook.mockReturnValue({
    facets: [
      { key: 'nginx', name: 'nginx', category: 'web_server', asset_count: 12 },
      { key: 'next.js', name: 'Next.js', category: 'framework', asset_count: 3 },
    ],
    isLoading: false,
  })
})

describe('InventoryTechnologiesFacet', () => {
  it('loads the options only once opened', () => {
    render(<InventoryTechnologiesFacet filters={{}} onChange={vi.fn()} />)
    expect(facetsHook).toHaveBeenLastCalledWith(undefined, false)
    fireEvent.click(screen.getByRole('button', { name: /Technologies/ }))
    expect(facetsHook).toHaveBeenLastCalledWith(undefined, true)
  })

  it('filters by a technology and by a category, back to page 1', () => {
    const onChange = setup({ page: 4 })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Next.js' }))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ technologies: ['next.js'], page: 1 })
    )
    fireEvent.click(screen.getByRole('checkbox', { name: 'CDN' }))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ technologyCategories: ['cdn'], page: 1 })
    )
  })

  it('keeps a selected technology visible when the list does not have it', () => {
    setup({ technologies: ['wordpress'] })
    expect(screen.getByRole('checkbox', { name: 'wordpress' })).toBeChecked()
  })
})

describe('technology filters in the URL', () => {
  it('round-trip and count', () => {
    const f = parseInventoryFilters(
      new URLSearchParams('technology=nginx,next.js&technology_category=cdn')
    )
    expect(f.technologies).toEqual(['nginx', 'next.js'])
    expect(f.technologyCategories).toEqual(['cdn'])
    expect(countActiveFilters(f)).toBe(3)
  })
})

describe('technology filters on the API query', () => {
  it('sends technology and technology_category', async () => {
    const { buildAssetQueryParams } = await vi.importActual<
      typeof import('../../../hooks/use-assets')
    >('../../../hooks/use-assets')
    const p = buildAssetQueryParams({
      technologies: ['nginx', 'next.js'],
      technologyCategories: ['cdn'],
    })
    expect(p.technology).toBe('nginx,next.js')
    expect(p.technology_category).toBe('cdn')
    expect(buildAssetQueryParams({}).technology).toBeUndefined()
  })
})
