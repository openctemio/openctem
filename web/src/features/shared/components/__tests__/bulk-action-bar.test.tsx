import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { BulkActionBar } from '../bulk-action-bar'

describe('BulkActionBar', () => {
  it('renders nothing when no rows are selected', () => {
    const { container } = render(
      <BulkActionBar count={0} onClear={() => {}}>
        <button>Assign</button>
      </BulkActionBar>
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the count and the actions as a toolbar', () => {
    render(
      <BulkActionBar count={3} onClear={() => {}} noun="findings selected">
        <button>Assign</button>
      </BulkActionBar>
    )
    expect(screen.getByRole('toolbar')).toBeInTheDocument()
    expect(screen.getByRole('toolbar')).toHaveTextContent(/^3 findings selected/)
    expect(screen.getByText('findings selected')).toHaveClass('sr-only', 'sm:not-sr-only')
    expect(screen.getByRole('button', { name: 'Assign' })).toBeInTheDocument()
  })

  it('clears via its button and via Escape', () => {
    const onClear = vi.fn()
    render(
      <BulkActionBar count={2} onClear={onClear}>
        <span />
      </BulkActionBar>
    )
    fireEvent.click(screen.getByRole('button', { name: /clear selection/i }))
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onClear).toHaveBeenCalledTimes(2)
  })

  it('stays open with nothing selected when asked, its actions disabled', () => {
    render(
      <BulkActionBar count={0} open onClear={() => {}}>
        <button>Assign</button>
      </BulkActionBar>
    )
    expect(screen.getByRole('toolbar')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Assign' })).toBeDisabled()
  })

  it('keeps room for itself under the page while it shows', () => {
    const { unmount } = render(
      <BulkActionBar count={1} onClear={() => {}}>
        <button>Assign</button>
      </BulkActionBar>
    )
    expect(document.documentElement.style.getPropertyValue('--bulk-bar-space')).toMatch(/px$/)
    unmount()
    expect(document.documentElement.style.getPropertyValue('--bulk-bar-space')).toBe('')
  })

  it('makes the count a menu on a phone when given selection items', () => {
    render(
      <BulkActionBar
        count={2}
        onClear={() => {}}
        status={<button>Select all 9 that match</button>}
        selectMenu={<span>items</span>}
      >
        <button>Assign</button>
      </BulkActionBar>
    )
    const trigger = screen.getByRole('button', { name: '2 selected: selection options' })
    expect(trigger).toHaveClass('md:hidden')
    // The offer lives in the menu on a phone, beside the count on a desktop.
    expect(
      screen.getByRole('button', { name: 'Select all 9 that match' }).parentElement
    ).toHaveClass('max-md:hidden')
  })

  it('leaves the selection alone when Escape closes a menu', () => {
    const onClear = vi.fn()
    render(
      <>
        <div role="menu">
          <button>Item</button>
        </div>
        <BulkActionBar count={2} onClear={onClear}>
          <span />
        </BulkActionBar>
      </>
    )
    fireEvent.keyDown(screen.getByRole('button', { name: 'Item' }), { key: 'Escape' })
    expect(onClear).not.toHaveBeenCalled()
  })
})
