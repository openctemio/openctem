import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useCommittedSearch } from '../use-committed-search'

/**
 * The URL holds the settled search; the hook keeps the box. The harness plays
 * the router: a commit becomes the next URL value only when the test says the
 * navigation has landed (rerender), which is where keys used to be lost.
 */
function setup(initial?: string) {
  const commits: string[] = []
  const hook = renderHook(
    ({ url }: { url?: string }) => useCommittedSearch(url, (t) => commits.push(t)),
    { initialProps: { url: initial } }
  )
  return { hook, commits }
}

describe('useCommittedSearch', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('keeps keys typed while its own write is on the way back from the URL', () => {
    const { hook, commits } = setup()
    act(() => hook.result.current[1]('re'))
    act(() => vi.advanceTimersByTime(350))
    expect(commits).toEqual(['re'])
    // More keys before the navigation lands...
    act(() => hook.result.current[1]('reo'))
    act(() => hook.result.current[1]('repo'))
    // ...then the URL comes back with "re": the box must keep "repo".
    hook.rerender({ url: 're' })
    expect(hook.result.current[0]).toBe('repo')
    act(() => vi.advanceTimersByTime(350))
    expect(commits).toEqual(['re', 'repo'])
  })

  it('takes a search set elsewhere (a saved view, back and forward)', () => {
    const { hook } = setup('old')
    expect(hook.result.current[0]).toBe('old')
    hook.rerender({ url: 'web-01' })
    expect(hook.result.current[0]).toBe('web-01')
  })

  it('empties the box when the search is cleared elsewhere', () => {
    const { hook, commits } = setup()
    act(() => hook.result.current[1]('api'))
    act(() => vi.advanceTimersByTime(350))
    hook.rerender({ url: 'api' })
    expect(commits).toEqual(['api'])
    hook.rerender({ url: undefined })
    expect(hook.result.current[0]).toBe('')
  })

  it('does not write the URL value back to the URL', () => {
    const { commits } = setup('web')
    act(() => vi.advanceTimersByTime(350))
    expect(commits).toEqual([])
  })
})
