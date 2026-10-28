import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import type { InventoryFilters } from '../../../lib/inventory-url'

const tagsHook = vi.fn()
vi.mock('../../../hooks/use-asset-tags', () => ({
  useAssetTags: (...args: unknown[]) => tagsHook(...args),
}))

import { InventoryTagsFacet } from '../inventory-tags-facet'

function setup(filters: InventoryFilters, opts: { types?: string[] } = {}) {
  const onChange = vi.fn()
  render(<InventoryTagsFacet filters={filters} onChange={onChange} types={opts.types} />)
  // The section starts folded unless something is selected.
  const header = screen.getByRole('button', { name: /Tags/ })
  if (header.getAttribute('aria-expanded') === 'false') fireEvent.click(header)
  return onChange
}

beforeEach(() => {
  tagsHook.mockReset()
  tagsHook.mockReturnValue({
    tags: ['prod', 'pci', 'team-a', 't4', 't5', 't6', 't7', 't8'],
    systemTags: ['bug-bounty', 'program:acme:shop'],
    isLoading: false,
  })
})

describe('InventoryTagsFacet', () => {
  it('asks for the tag list with the system tags, narrowed to the typed list', () => {
    setup({}, { types: ['domain'] })
    expect(tagsHook).toHaveBeenCalledWith(
      undefined,
      true,
      ['domain'],
      expect.objectContaining({ includeSystem: true })
    )
  })

  it('lists the most used tags first and the rest on demand', () => {
    setup({})
    expect(screen.getByTestId('tag-facet-row-prod')).toBeInTheDocument()
    expect(screen.queryByTestId('tag-facet-row-t7')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Show 2 more' }))
    expect(screen.getByTestId('tag-facet-row-t8')).toBeInTheDocument()
  })

  it('includes a tag with its checkbox', () => {
    const onChange = setup({ page: 3 })
    fireEvent.click(within(screen.getByTestId('tag-facet-row-pci')).getByRole('checkbox'))
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ tags: ['pci'], page: 1 }))
  })

  it('excludes a tag with its minus button', () => {
    const onChange = setup({ tags: ['pci'] })
    fireEvent.click(screen.getByRole('button', { name: 'Exclude pci' }))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ tags: undefined, excludeTags: ['pci'] })
    )
  })

  it('shows Any / All only with two or more included tags', () => {
    setup({ tags: ['pci'] })
    expect(screen.queryByRole('radiogroup')).not.toBeInTheDocument()
  })

  it('switches the match mode to All', () => {
    const onChange = setup({ tags: ['pci', 'prod'] })
    const all = screen.getByRole('radio', { name: 'All' })
    expect(screen.getByRole('radio', { name: 'Any' })).toHaveAttribute('aria-checked', 'true')
    fireEvent.click(all)
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ tagsMode: 'all', page: 1 }))
  })

  it('groups the system tags apart, and they filter the same way', () => {
    const onChange = setup({})
    expect(screen.getByText('System tags')).toBeInTheDocument()
    const row = screen.getByTestId('tag-facet-row-program:acme:shop')
    expect(within(row).getByLabelText('Set by the platform, read-only')).toBeInTheDocument()
    fireEvent.click(within(row).getByRole('checkbox'))
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ tags: ['program:acme:shop'] }))
  })

  it('keeps a selected tag from the URL visible and removable when the list lacks it', () => {
    const onChange = setup({ tags: ['legacy-only'], excludeTags: ['gone'] })
    const row = screen.getByTestId('tag-facet-row-legacy-only')
    expect(within(row).getByRole('checkbox')).toBeChecked()
    expect(screen.getByRole('button', { name: 'Exclude gone' })).toHaveAttribute(
      'aria-pressed',
      'true'
    )
    fireEvent.click(within(row).getByRole('checkbox'))
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ tags: undefined }))
  })

  it('says so when the workspace has no tags', () => {
    tagsHook.mockReturnValue({ tags: [], systemTags: [], isLoading: false })
    setup({})
    expect(screen.getByText('No tags in this organization yet.')).toBeInTheDocument()
  })
})
