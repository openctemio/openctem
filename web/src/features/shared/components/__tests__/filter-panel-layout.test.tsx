import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { FilterPanelSlot, useFilterPanelOpen } from '../filter-panel-layout'
import { FilterPanelToggle } from '../filter-button'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const KEY = 'openctem:test-filters-open'

function Page({ children }: { children?: React.ReactNode }) {
  const [open, setOpen] = useFilterPanelOpen(KEY)
  return (
    <div>
      <FilterPanelToggle
        open={open}
        onToggle={() => setOpen((o) => !o)}
        onOpenSheet={() => {}}
        activeCount={2}
        controlsId="test-filters"
      />
      <FilterPanelSlot open={open} id="test-filters" label="Test filters">
        {children ?? <button>facet</button>}
      </FilterPanelSlot>
    </div>
  )
}

describe('useFilterPanelOpen + FilterPanelSlot', () => {
  beforeEach(() => window.localStorage.clear())

  it('starts closed: no facet mounted, the slot is inert', () => {
    const { container } = render(<Page />)
    expect(screen.queryByText('facet')).toBeNull()
    expect(container.querySelector('#test-filters')?.parentElement).toHaveAttribute('inert')
  })

  it('toggles open, shows the active count, and remembers the choice', () => {
    const { container, unmount } = render(<Page />)
    const toggle = screen.getAllByRole('button', { name: /Filters/ })[0]
    expect(toggle).toHaveAttribute('data-active')
    expect(toggle.querySelector('[data-slot="filter-count"]')).toHaveTextContent('2')
    fireEvent.click(toggle)
    expect(screen.getByText('facet')).toBeInTheDocument()
    expect(toggle).toHaveAttribute('aria-pressed', 'true')
    expect(toggle).toHaveAttribute('aria-controls', 'test-filters')
    expect(container.querySelector('#test-filters')?.parentElement).not.toHaveAttribute('inert')
    expect(window.localStorage.getItem(KEY)).toBe('1')
    unmount()
    render(<Page />)
    expect(screen.getByText('facet')).toBeInTheDocument()
  })

  it('keeps the contents mounted after closing so it can animate', () => {
    render(<Page />)
    const toggle = screen.getAllByRole('button', { name: /Filters/ })[0]
    fireEvent.click(toggle)
    fireEvent.click(toggle)
    expect(screen.getByText('facet')).toBeInTheDocument()
    expect(window.localStorage.getItem(KEY)).toBe('0')
  })

  it('works when storage throws', () => {
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    render(<Page />)
    fireEvent.click(screen.getAllByRole('button', { name: /Filters/ })[0])
    expect(screen.getByText('facet')).toBeInTheDocument()
    get.mockRestore()
    set.mockRestore()
  })
})
