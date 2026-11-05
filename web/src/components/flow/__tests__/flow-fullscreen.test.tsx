import * as React from 'react'
import { beforeAll, describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { FlowCanvas } from '../flow-canvas'
import { FlowFullscreen } from '../flow-fullscreen'

beforeAll(() => {
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver
})

/** A page that keeps a counter above the full-screen view (its own state). */
function Page() {
  const [count, setCount] = React.useState(0)
  return (
    <FlowFullscreen title="Graph of x">
      {(full) => (
        <div>
          <span data-testid="mode">{full ? 'full' : 'inline'}</span>
          <button type="button" onClick={() => setCount((c) => c + 1)}>
            count {count}
          </button>
          <input aria-label="search" />
          <div style={{ height: 200 }}>
            <FlowCanvas nodes={[]} edges={[]} nodeTypes={{}} label="Test graph" help="keys" />
          </div>
        </div>
      )}
    </FlowFullscreen>
  )
}

describe('FlowFullscreen', () => {
  it('opens the same view full screen from the canvas button and keeps the page state', () => {
    render(<Page />)
    expect(screen.getByTestId('mode')).toHaveTextContent('inline')
    fireEvent.click(screen.getByRole('button', { name: /count 0/ }))
    fireEvent.click(screen.getByTestId('flow-fullscreen-toggle'))

    const dialog = screen.getByRole('dialog', { name: 'Graph of x' })
    expect(dialog).toBeInTheDocument()
    expect(screen.getAllByTestId('mode')).toHaveLength(1)
    expect(screen.getByTestId('mode')).toHaveTextContent('full')
    // The page's own state carried over.
    expect(screen.getByRole('button', { name: /count 1/ })).toBeInTheDocument()
    // Inside full screen the button leaves it.
    fireEvent.click(screen.getByTestId('flow-fullscreen-toggle'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByTestId('mode')).toHaveTextContent('inline')
  })

  it('toggles with f, but not while typing, and leaves with Escape', () => {
    render(<Page />)
    fireEvent.keyDown(screen.getByRole('textbox', { name: 'search' }), { key: 'f' })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.keyDown(screen.getByRole('button', { name: /count/ }), { key: 'f', ctrlKey: true })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

    fireEvent.keyDown(screen.getByRole('button', { name: /count/ }), { key: 'f' })
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

    fireEvent.keyDown(screen.getByRole('button', { name: /count/ }), { key: 'f' })
    fireEvent.keyDown(screen.getByRole('button', { name: /count/ }), { key: 'f' })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('a canvas outside FlowFullscreen has no full-screen button', () => {
    render(
      <div style={{ height: 200 }}>
        <FlowCanvas nodes={[]} edges={[]} nodeTypes={{}} label="Plain" help="keys" />
      </div>
    )
    expect(screen.queryByTestId('flow-fullscreen-toggle')).not.toBeInTheDocument()
  })
})
