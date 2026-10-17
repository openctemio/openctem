import { describe, expect, it, afterEach } from 'vitest'
import { neighbour, readFindingHash, writeFindingHash } from '../use-drawer-navigation'

describe('drawer navigation', () => {
  afterEach(() => window.history.replaceState(null, '', '/findings'))

  it('moves to the next and previous finding of the list', () => {
    const items = [{ id: 'a' }, { id: 'b' }, { id: 'c' }]
    expect(neighbour(items, 'b', 'j')?.id).toBe('c')
    expect(neighbour(items, 'b', 'k')?.id).toBe('a')
    expect(neighbour(items, 'c', 'j')).toBeUndefined()
    expect(neighbour(items, 'zz', 'j')).toBeUndefined()
  })

  it('keeps the open finding in the hash without touching the query', () => {
    window.history.replaceState(null, '', '/findings?severity=critical')
    writeFindingHash('01a13d80-8b0c-7cab-980f-05f7104549c3')
    expect(window.location.search).toBe('?severity=critical')
    expect(readFindingHash()).toBe('01a13d80-8b0c-7cab-980f-05f7104549c3')
    writeFindingHash(null)
    expect(window.location.hash).toBe('')
  })

  it('ignores a hash that is not an id', () => {
    expect(readFindingHash('#finding=<script>')).toBeNull()
    expect(readFindingHash('#other=1')).toBeNull()
  })
})
