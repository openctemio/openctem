import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { useUnsavedChangesGuard } from '../use-unsaved-changes-guard'

function Page({ dirty, onBlocked }: { dirty: boolean; onBlocked: (href: string) => void }) {
  useUnsavedChangesGuard(dirty, onBlocked)
  return (
    <>
      {/* eslint-disable-next-line @next/next/no-html-link-for-pages -- a plain anchor is what the guard intercepts */}
      <a href="/findings?x=1">in app</a>
      <a href="https://other.example/">outside</a>
      <a href="/new-tab" target="_blank">
        new tab
      </a>
    </>
  )
}

describe('useUnsavedChangesGuard', () => {
  it('holds in-app links while dirty', () => {
    const onBlocked = vi.fn()
    render(<Page dirty onBlocked={onBlocked} />)
    const ev = fireEvent.click(screen.getByText('in app'))
    expect(ev).toBe(false) // default prevented
    expect(onBlocked).toHaveBeenCalledWith('/findings?x=1')
  })

  it('lets other links and clean pages through', () => {
    const onBlocked = vi.fn()
    const { rerender } = render(<Page dirty onBlocked={onBlocked} />)
    fireEvent.click(screen.getByText('outside'))
    fireEvent.click(screen.getByText('new tab'))
    fireEvent.click(screen.getByText('in app'), { ctrlKey: true })
    expect(onBlocked).not.toHaveBeenCalled()
    rerender(<Page dirty={false} onBlocked={onBlocked} />)
    fireEvent.click(screen.getByText('in app'))
    expect(onBlocked).not.toHaveBeenCalled()
  })

  it('asks the browser before unload while dirty', () => {
    render(<Page dirty onBlocked={() => {}} />)
    const e = new Event('beforeunload', { cancelable: true })
    window.dispatchEvent(e)
    expect(e.defaultPrevented).toBe(true)
  })
})
