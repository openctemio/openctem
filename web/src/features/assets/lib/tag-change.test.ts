import { describe, expect, it } from 'vitest'

import { isEmptyTagChange, tagChange } from './tag-change'

describe('tagChange', () => {
  it('names only what the person added and removed', () => {
    expect(tagChange(['team:web', 'pci'], ['pci', 'prod'])).toEqual({
      tagsAdd: ['prod'],
      tagsRemove: ['team:web'],
    })
  })

  it('is empty when the tags are the same, in any order', () => {
    expect(isEmptyTagChange(tagChange(['a', 'b'], ['b', 'a']))).toBe(true)
  })

  it('never removes a tag the person was not shown', () => {
    // The stored list may hold tags set after the copy was loaded: they are
    // not in `shown`, so the change cannot name them.
    const c = tagChange(['a'], ['a', 'b'])
    expect(c.tagsRemove).toEqual([])
    expect(c.tagsAdd).toEqual(['b'])
  })

  it('keeps a tag that contains a comma whole', () => {
    expect(tagChange(['a,b'], ['a,b', 'c'])).toEqual({ tagsAdd: ['c'], tagsRemove: [] })
  })
})
