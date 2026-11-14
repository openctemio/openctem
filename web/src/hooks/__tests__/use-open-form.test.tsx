import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render } from '@testing-library/react'

vi.mock('next/navigation', () => ({ usePathname: () => window.location.pathname }))

import { useOpenForm } from '../use-open-form'

function Page({ allowed, open }: { allowed: boolean; open: () => void }) {
  useOpenForm('finding', allowed, open)
  return null
}

const go = (url: string) => window.history.pushState(null, '', url)

describe('useOpenForm', () => {
  const open = vi.fn()
  beforeEach(() => {
    open.mockReset()
    window.history.replaceState(null, '', '/findings')
  })
  afterEach(() => cleanup())

  it('opens the form once and removes the flag from the current history entry', async () => {
    go('/findings?new=finding&severity=high')
    render(<Page allowed open={open} />)
    await act(async () => {})
    expect(open).toHaveBeenCalledTimes(1)
    expect(window.location.search).toBe('?severity=high')
  })

  it('does not open again when the page mounts again on that entry (Back / Forward)', async () => {
    go('/findings?new=finding')
    const first = render(<Page allowed open={open} />)
    await act(async () => {})
    first.unmount()
    render(<Page allowed open={open} />)
    await act(async () => {})
    expect(open).toHaveBeenCalledTimes(1)
  })

  it('opens when the flag arrives on the page already showing', async () => {
    render(<Page allowed open={open} />)
    await act(async () => {})
    expect(open).not.toHaveBeenCalled()
    await act(async () => {
      go('/findings?new=finding')
      await Promise.resolve()
    })
    expect(open).toHaveBeenCalledTimes(1)
    expect(window.location.search).toBe('')
  })

  it('without the page permission it opens nothing and leaves the flag', async () => {
    go('/findings?new=finding')
    render(<Page allowed={false} open={open} />)
    await act(async () => {})
    expect(open).not.toHaveBeenCalled()
    expect(window.location.search).toBe('?new=finding')
  })

  it('ignores a flag for another form', async () => {
    go('/findings?new=import')
    render(<Page allowed open={open} />)
    await act(async () => {})
    expect(open).not.toHaveBeenCalled()
    expect(window.location.search).toBe('?new=import')
  })
})
