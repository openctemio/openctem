import { describe, expect, it, afterEach, vi } from 'vitest'
import { renderHook } from '@testing-library/react'
import {
  findingListPosition,
  neighbour,
  readFindingHash,
  useDrawerKeyboardNav,
  writeFindingHash,
} from '../use-drawer-navigation'

const press = (key: string, target: Element | Document = document) =>
  target.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true }))

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

  it('places the open finding in the whole list, not only the page', () => {
    const items = [{ id: 'a' }, { id: 'b' }, { id: 'c' }]
    const onSelect = vi.fn()
    const first = findingListPosition({
      items,
      currentId: 'a',
      page: 1,
      perPage: 3,
      total: 418,
      onSelect,
    })
    expect(first).toMatchObject({ index: 1, total: 418 })
    expect(first?.onPrev).toBeUndefined()
    first?.onNext?.()
    expect(onSelect).toHaveBeenLastCalledWith({ id: 'b' })

    const last = findingListPosition({
      items,
      currentId: 'c',
      page: 3,
      perPage: 3,
      total: 418,
      onSelect,
    })
    expect(last).toMatchObject({ index: 9, total: 418 })
    expect(last?.onNext).toBeUndefined()
    last?.onPrev?.()
    expect(onSelect).toHaveBeenLastCalledWith({ id: 'b' })
  })

  it('has no position for a finding that is not a row of the page', () => {
    const items = [{ id: 'a' }]
    const onSelect = vi.fn()
    expect(findingListPosition({ items, currentId: 'zz', total: 5, onSelect })).toBeUndefined()
    expect(findingListPosition({ items, currentId: undefined, total: 5, onSelect })).toBeUndefined()
  })

  it('j and k open the next and previous finding while the drawer is open', () => {
    const items = [{ id: 'a' }, { id: 'b' }, { id: 'c' }]
    const onSelect = vi.fn()
    const { rerender, unmount } = renderHook(
      (p: { open: boolean; currentId: string }) => useDrawerKeyboardNav({ ...p, items, onSelect }),
      { initialProps: { open: true, currentId: 'b' } }
    )
    press('j')
    expect(onSelect).toHaveBeenLastCalledWith({ id: 'c' })
    press('k')
    expect(onSelect).toHaveBeenLastCalledWith({ id: 'a' })

    // Typing in a field of the drawer is not a move.
    const input = document.body.appendChild(document.createElement('input'))
    onSelect.mockClear()
    press('j', input)
    expect(onSelect).not.toHaveBeenCalled()
    input.remove()

    // Nothing past the ends, and nothing while closed.
    rerender({ open: true, currentId: 'c' })
    press('j')
    rerender({ open: false, currentId: 'b' })
    press('j')
    expect(onSelect).not.toHaveBeenCalled()
    unmount()
  })
})
