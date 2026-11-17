import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { isPlainClick, RowNameLink } from '../row-name-link'

function setup(onRow = vi.fn()) {
  const onOpen = vi.fn()
  render(
    <div onClick={onRow}>
      <RowNameLink
        href="/scans/abc"
        onOpen={onOpen}
        label="Nightly scan, view details"
        title="Nightly scan"
      >
        Nightly scan
      </RowNameLink>
    </div>
  )
  const link = screen.getByRole('link', { name: 'Nightly scan, view details' })
  return { link, onOpen, onRow }
}

describe('RowNameLink', () => {
  it('is a real link to the detail page with the full text as its tooltip', () => {
    const { link } = setup()
    expect(link).toHaveAttribute('href', '/scans/abc')
    expect(link).toHaveAttribute('title', 'Nightly scan')
    expect(link).toHaveAttribute('data-slot', 'row-name-link')
    expect(link).toHaveClass('truncate', 'min-w-0')
    expect(link).toHaveTextContent('Nightly scan')
  })

  it('cuts its one line alone in a cell: a box no wider than the cell, no wrapper needed', () => {
    const { link } = setup()
    // An inline anchor ignores `truncate`; an inline box capped at its cell does not.
    expect(link).toHaveClass('inline-block', 'max-w-full', 'truncate')
  })

  it('a plain click opens the overlay and does not navigate', () => {
    const { link, onOpen, onRow } = setup()
    // fireEvent returns false when the default action was prevented.
    expect(fireEvent.click(link)).toBe(false)
    expect(onOpen).toHaveBeenCalledOnce()
    // The row does not open the overlay as well.
    expect(onRow).not.toHaveBeenCalled()
  })

  it.each([
    ['Ctrl', { ctrlKey: true }],
    ['Cmd', { metaKey: true }],
    ['Shift', { shiftKey: true }],
    ['Alt', { altKey: true }],
    ['a middle button', { button: 1 }],
  ])('a click with %s follows the link', (_name, init) => {
    const { link, onOpen, onRow } = setup()
    // jsdom does not navigate; a listener after the link's own stops it there.
    link.addEventListener('click', (e) => e.preventDefault())
    const event = new MouseEvent('click', { bubbles: true, cancelable: true, ...init })
    const prevented = vi.spyOn(event, 'preventDefault')
    fireEvent(link, event)
    // Only the test's own listener prevented it: the link left it to the browser.
    expect(prevented).toHaveBeenCalledTimes(1)
    expect(onOpen).not.toHaveBeenCalled()
    expect(onRow).not.toHaveBeenCalled()
  })

  it('takes the slot name and two lines from its caller', () => {
    render(
      <RowNameLink href="/findings/f-1" onOpen={() => {}} slot="finding-title-link" lines={2}>
        Title
      </RowNameLink>
    )
    const link = screen.getByRole('link', { name: 'Title' })
    expect(link).toHaveAttribute('data-slot', 'finding-title-link')
    expect(link).toHaveClass('line-clamp-2')
    expect(link).not.toHaveClass('truncate')
    expect(link).not.toHaveClass('inline-block')
  })

  it('follows only a path of this app', () => {
    render(
      <>
        <RowNameLink href="https://example.com/x" onOpen={() => {}}>
          Outside
        </RowNameLink>
        <RowNameLink href="javascript:alert(1)" onOpen={() => {}}>
          Script
        </RowNameLink>
      </>
    )
    expect(screen.getByRole('link', { name: 'Outside' })).toHaveAttribute('href', '#')
    expect(screen.getByRole('link', { name: 'Script' })).toHaveAttribute('href', '#')
  })

  it('isPlainClick: the primary button with no modifier key', () => {
    const base = { button: 0, metaKey: false, ctrlKey: false, shiftKey: false, altKey: false }
    expect(isPlainClick(base)).toBe(true)
    expect(isPlainClick({ ...base, button: 1 })).toBe(false)
    expect(isPlainClick({ ...base, metaKey: true })).toBe(false)
    expect(isPlainClick({ ...base, ctrlKey: true })).toBe(false)
    expect(isPlainClick({ ...base, shiftKey: true })).toBe(false)
    expect(isPlainClick({ ...base, altKey: true })).toBe(false)
  })
})
