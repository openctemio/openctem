import { describe, expect, it } from 'vitest'
import {
  countActiveFilters,
  isInventoryFilterEmpty,
  parseInventoryFilters,
  serializeInventoryFilters,
  toggleExcludedTag,
  toggleIncludedTag,
  type InventoryFilters,
} from './inventory-url'

describe('inventory tag filter in the URL', () => {
  it('round-trips tags, the All mode and excluded tags', () => {
    const f: InventoryFilters = { tags: ['pci', 'prod'], tagsMode: 'all', excludeTags: ['retired'] }
    const qs = serializeInventoryFilters(f)
    expect(qs.get('tags')).toBe('pci,prod')
    expect(qs.get('tags_mode')).toBe('all')
    expect(qs.get('exclude_tags')).toBe('retired')
    expect(parseInventoryFilters(qs)).toEqual(f)
  })

  it('never writes the default Any mode, nor a mode without tags', () => {
    expect(serializeInventoryFilters({ tags: ['a'], tagsMode: 'any' }).has('tags_mode')).toBe(false)
    expect(serializeInventoryFilters({ tagsMode: 'all' }).has('tags_mode')).toBe(false)
    expect(parseInventoryFilters(new URLSearchParams('tags=a&tags_mode=bogus')).tagsMode).toBe(
      undefined
    )
  })

  it('counts included and excluded tags on the toolbar, but not the mode', () => {
    const f: InventoryFilters = { tags: ['a', 'b'], tagsMode: 'all', excludeTags: ['c'] }
    expect(countActiveFilters(f)).toBe(3)
    expect(isInventoryFilterEmpty({ excludeTags: ['c'] })).toBe(false)
  })
})

describe('toggling a tag', () => {
  it('adds and removes an included tag, back to page 1', () => {
    const once = toggleIncludedTag({ page: 4 }, 'pci')
    expect(once).toMatchObject({ tags: ['pci'], page: 1 })
    expect(toggleIncludedTag(once, 'pci').tags).toBeUndefined()
  })

  it('moves a tag between include and exclude, never both', () => {
    const inc = toggleIncludedTag({ excludeTags: ['pci', 'old'] }, 'pci')
    expect(inc.tags).toEqual(['pci'])
    expect(inc.excludeTags).toEqual(['old'])
    const exc = toggleExcludedTag(inc, 'pci')
    expect(exc.tags).toBeUndefined()
    expect(exc.excludeTags).toEqual(['old', 'pci'])
  })

  it('keeps the match mode while tags remain and drops it with the last one', () => {
    const f: InventoryFilters = { tags: ['a', 'b'], tagsMode: 'all' }
    expect(toggleIncludedTag(f, 'a').tagsMode).toBe('all')
    expect(toggleIncludedTag({ tags: ['a'], tagsMode: 'all' }, 'a').tagsMode).toBeUndefined()
  })
})

describe('tag filter on the API query', () => {
  it('sends tags, tags_mode=all and exclude_tags', async () => {
    const { buildAssetQueryParams } = await import('../hooks/use-assets')
    expect(
      buildAssetQueryParams({ tags: ['a', 'b'], tagsMode: 'all', excludeTags: ['c'] })
    ).toMatchObject({
      tags: 'a,b',
      tags_mode: 'all',
      exclude_tags: 'c',
    })
    const any = buildAssetQueryParams({ tags: ['a'], tagsMode: 'any' })
    expect(any.tags_mode).toBeUndefined()
    // A mode without tags is not sent.
    expect(buildAssetQueryParams({ tagsMode: 'all' }).tags_mode).toBeUndefined()
  })
})
