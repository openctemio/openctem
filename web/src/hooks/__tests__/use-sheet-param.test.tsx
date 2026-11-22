import Link from 'next/link'
import { act, fireEvent, render, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  opensSheet,
  rowFocusTarget,
  sheetIdOf,
  sheetNeighbour,
  useSheetListNav,
  useSheetParam,
} from '../use-sheet-param'

const flush = () => act(async () => await Promise.resolve())

describe('sheetIdOf', () => {
  it('accepts ids and refuses anything that could leave the API path', () => {
    expect(sheetIdOf('3f2b8c1e-0000-4000-8000-000000000001')).toBe(
      '3f2b8c1e-0000-4000-8000-000000000001'
    )
    expect(sheetIdOf('../admin')).toBeNull()
    expect(sheetIdOf('a/b')).toBeNull()
    expect(sheetIdOf('a?x=1')).toBeNull()
    expect(sheetIdOf('')).toBeNull()
    expect(sheetIdOf(null)).toBeNull()
    expect(sheetIdOf('x'.repeat(65))).toBeNull()
  })
})

describe('useSheetParam', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/remediation/tasks?view=mine')
  })

  it('reads the open record from the URL, so a reload or a shared link reopens it', () => {
    window.history.replaceState(null, '', '/remediation/tasks?view=mine&task=t1')
    const { result } = renderHook(() => useSheetParam('task'))
    expect(result.current.id).toBe('t1')
  })

  it('ignores a value that is not an id', () => {
    window.history.replaceState(null, '', '/remediation/tasks?task=..%2Fx')
    const { result } = renderHook(() => useSheetParam('task'))
    expect(result.current.id).toBeNull()
  })

  it('open pushes an entry and keeps the filters; move replaces it', async () => {
    const { result } = renderHook(() => useSheetParam('task'))
    const before = window.history.length
    act(() => result.current.open('t1'))
    await flush()
    expect(window.location.search).toBe('?view=mine&task=t1')
    expect(window.history.length).toBe(before + 1)
    expect(result.current.id).toBe('t1')

    act(() => result.current.move('t2'))
    await flush()
    expect(window.location.search).toBe('?view=mine&task=t2')
    expect(window.history.length).toBe(before + 1)
    expect(result.current.id).toBe('t2')
  })

  it('close goes Back after its own open, so Back and Close agree', async () => {
    const back = vi.spyOn(window.history, 'back').mockImplementation(() => {})
    const { result } = renderHook(() => useSheetParam('task'))
    act(() => result.current.open('t1'))
    await flush()
    act(() => result.current.close())
    expect(back).toHaveBeenCalledTimes(1)
    back.mockRestore()
  })

  it('close of a sheet opened from a link removes the parameter in place', async () => {
    window.history.replaceState(null, '', '/remediation/tasks?view=mine&task=t1')
    const back = vi.spyOn(window.history, 'back')
    const { result } = renderHook(() => useSheetParam('task'))
    act(() => result.current.close())
    await flush()
    expect(back).not.toHaveBeenCalled()
    expect(window.location.search).toBe('?view=mine')
    expect(result.current.id).toBeNull()
    back.mockRestore()
  })
})

describe('sheetNeighbour', () => {
  const ids = ['a', 'b', 'c']
  it('moves with the arrows and j / k, and stops at the ends', () => {
    expect(sheetNeighbour(ids, 'b', 'ArrowDown')).toBe('c')
    expect(sheetNeighbour(ids, 'b', 'j')).toBe('c')
    expect(sheetNeighbour(ids, 'b', 'ArrowUp')).toBe('a')
    expect(sheetNeighbour(ids, 'b', 'k')).toBe('a')
    expect(sheetNeighbour(ids, 'c', 'ArrowDown')).toBeUndefined()
    expect(sheetNeighbour(ids, 'a', 'k')).toBeUndefined()
    expect(sheetNeighbour(ids, 'x', 'j')).toBeUndefined()
    expect(sheetNeighbour(ids, 'b', 'Enter')).toBeUndefined()
  })
})

describe('useSheetListNav', () => {
  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('moves to the next and previous row only while a sheet is open', () => {
    const onMove = vi.fn()
    const { rerender } = renderHook(
      ({ current }: { current: string | null }) =>
        useSheetListNav({ ids: ['a', 'b', 'c'], currentId: current, onMove }),
      { initialProps: { current: null as string | null } }
    )
    fireEvent.keyDown(document.body, { key: 'ArrowDown' })
    expect(onMove).not.toHaveBeenCalled()

    rerender({ current: 'b' })
    fireEvent.keyDown(document.body, { key: 'ArrowDown' })
    fireEvent.keyDown(document.body, { key: 'k' })
    expect(onMove.mock.calls).toEqual([['c'], ['a']])
  })

  it('leaves the keys to a field, a menu and modified presses', () => {
    const onMove = vi.fn()
    renderHook(() => useSheetListNav({ ids: ['a', 'b'], currentId: 'a', onMove }))
    const { getByRole } = render(
      <div>
        <input aria-label="note" />
        <div role="menu" tabIndex={0} aria-label="menu" />
      </div>
    )
    fireEvent.keyDown(getByRole('textbox'), { key: 'ArrowDown' })
    fireEvent.keyDown(getByRole('menu'), { key: 'j' })
    fireEvent.keyDown(document.body, { key: 'ArrowDown', ctrlKey: true })
    fireEvent.keyDown(document.body, { key: 'j', shiftKey: true })
    expect(onMove).not.toHaveBeenCalled()
  })
})

describe('focus return and title links', () => {
  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('returns focus to the row title link of the record', () => {
    document.body.innerHTML =
      '<table><tbody><tr data-row-id="t1"><td><a href="/remediation/tasks/t1">T1</a></td></tr></tbody></table>'
    expect(rowFocusTarget('t1', '/remediation/tasks/t1')?.tagName).toBe('A')
    expect(rowFocusTarget('../x', '/remediation/tasks/t1')).toBeNull()
  })

  it('a plain click on a title opens the sheet; a ctrl-click stays a link', () => {
    const open = vi.fn()
    const { getByRole } = render(
      <Link href="/remediation/tasks/t1" onClick={(e) => opensSheet(e, open)}>
        T1
      </Link>
    )
    const link = getByRole('link')
    fireEvent.click(link, { ctrlKey: true })
    expect(open).not.toHaveBeenCalled()
    const plain = fireEvent.click(link)
    expect(open).toHaveBeenCalledTimes(1)
    expect(plain).toBe(false) // default prevented: no navigation
  })
})
