import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, cleanup } from '@testing-library/react'
import { Plus } from 'lucide-react'
import { useCreateChords, CHORD_WINDOW_MS } from '../use-create-chords'
import type { CreateAction } from '../use-create-actions'

const action = (id: CreateAction['id'], chord?: string): CreateAction => ({
  id,
  chord,
  labelKey: `nav.create.${id}`,
  label: id,
  icon: Plus,
  href: `/x?new=${id}`,
})

function Harness({ actions, run }: { actions: CreateAction[]; run: (a: CreateAction) => void }) {
  useCreateChords(actions, run)
  return <input aria-label="field" />
}

const press = (key: string, target: EventTarget = document.body, init: KeyboardEventInit = {}) =>
  target.dispatchEvent(
    new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...init })
  )

describe('useCreateChords', () => {
  const run = vi.fn()
  const pageKey = vi.fn()
  const onPage = (e: KeyboardEvent) => pageKey(e.key)
  beforeEach(() => {
    run.mockReset()
    pageKey.mockReset()
    document.addEventListener('keydown', onPage)
  })
  afterEach(() => {
    document.removeEventListener('keydown', onPage)
    cleanup()
    vi.useRealTimers()
  })

  it('"n" then "s" runs New scan', () => {
    render(<Harness actions={[action('scan', 's'), action('task', 't')]} run={run} />)
    press('n')
    press('s')
    expect(run).toHaveBeenCalledTimes(1)
    expect(run.mock.calls[0][0].id).toBe('scan')
  })

  it('"n t" never reaches a page as "t"', () => {
    render(<Harness actions={[action('task', 't')]} run={run} />)
    press('n')
    press('t')
    expect(run.mock.calls[0][0].id).toBe('task')
    expect(pageKey).not.toHaveBeenCalledWith('t')
  })

  it('a chord letter of an action the caller lacks does nothing and is still swallowed', () => {
    render(<Harness actions={[action('scan', 's')]} run={run} />)
    press('n')
    press('t')
    expect(run).not.toHaveBeenCalled()
    expect(pageKey).not.toHaveBeenCalledWith('t')
  })

  it('a single "t" without a chord reaches the page', () => {
    render(<Harness actions={[action('task', 't')]} run={run} />)
    press('t')
    expect(pageKey).toHaveBeenCalledWith('t')
    expect(run).not.toHaveBeenCalled()
  })

  it('does not start when a page took "n" itself (preventDefault on document)', () => {
    const takeN = (e: KeyboardEvent) => e.key === 'n' && e.preventDefault()
    document.addEventListener('keydown', takeN)
    render(<Harness actions={[action('scan', 's')]} run={run} />)
    press('n')
    press('s')
    document.removeEventListener('keydown', takeN)
    expect(run).not.toHaveBeenCalled()
    expect(pageKey).toHaveBeenCalledWith('s')
  })

  it('does not start while typing in a field', () => {
    const { getByLabelText } = render(<Harness actions={[action('scan', 's')]} run={run} />)
    const field = getByLabelText('field')
    press('n', field)
    press('s', field)
    expect(run).not.toHaveBeenCalled()
  })

  it('does not start with a modifier, and expires after the window', () => {
    vi.useFakeTimers()
    render(<Harness actions={[action('scan', 's')]} run={run} />)
    press('n', document.body, { ctrlKey: true })
    press('s')
    expect(run).not.toHaveBeenCalled()
    press('n')
    vi.advanceTimersByTime(CHORD_WINDOW_MS + 1)
    press('s')
    expect(run).not.toHaveBeenCalled()
    expect(pageKey).toHaveBeenCalledWith('s')
  })
})
