import { describe, it, expect, vi } from 'vitest'
import { createRef } from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  AddFilterButton,
  FilterButton,
  FilterPanelToggle,
  FilterPopover,
  ShowFilterPanelButton,
  useAddFilterShortcut,
} from '../filter-button'
import { FilterSheet } from '../filter-sheet'

// Radix Popover/Tooltip measure their content; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

describe('FilterButton', () => {
  it('keeps its own slot under a Radix trigger, so the search joins it', () => {
    render(
      <Popover>
        <PopoverTrigger asChild>
          <FilterButton />
        </PopoverTrigger>
        <PopoverContent>x</PopoverContent>
      </Popover>
    )
    expect(screen.getByRole('button', { name: 'Filters' })).toHaveAttribute(
      'data-slot',
      'filter-button'
    )
  })

  it('FilterPopover is the one trigger of a list with a few filter fields', () => {
    render(
      <FilterPopover open={false} onOpenChange={() => {}} activeCount={2} title="Filters">
        <p>fields</p>
      </FilterPopover>
    )
    const btn = screen.getByRole('button', { name: 'Filters, 2 active' })
    expect(btn).toHaveAttribute('data-slot', 'filter-button')
  })

  it('is an icon-only button named "Filters" with no visible text', () => {
    render(<FilterButton />)
    const btn = screen.getByRole('button', { name: 'Filters' })
    expect(btn).toHaveTextContent('')
    expect(btn.querySelector('svg')).not.toBeNull()
    expect(btn).toHaveClass('size-control', 'max-md:size-control-touch')
    expect(btn).not.toHaveAttribute('aria-pressed')
    expect(btn).not.toHaveAttribute('data-active')
  })

  it('shows the active count inside the button and in its accessible name', () => {
    render(<FilterButton activeCount={3} />)
    const btn = screen.getByRole('button', { name: 'Filters, 3 active' })
    expect(btn).toHaveAttribute('data-active')
    const badge = btn.querySelector('[data-slot="filter-count"]')
    expect(badge).toHaveTextContent('3')
    expect(badge).toHaveAttribute('aria-hidden', 'true')
    // Inside the square, beside the icon: never placed on the border.
    expect(badge?.className).not.toMatch(/absolute|-top-|-end-/)
    expect(btn).toHaveClass('size-control', 'max-md:size-control-touch')
  })

  it('says 9+ above nine and keeps the exact count in the name', () => {
    render(<FilterButton activeCount={150} />)
    const btn = screen.getByRole('button', { name: 'Filters, 150 active' })
    expect(btn.querySelector('[data-slot="filter-count"]')).toHaveTextContent('9+')
  })

  it('reports aria-pressed when toggling a panel', () => {
    const { rerender } = render(<FilterButton panelOpen={false} />)
    expect(screen.getByRole('button')).toHaveAttribute('aria-pressed', 'false')
    rerender(<FilterButton panelOpen />)
    expect(screen.getByRole('button')).toHaveAttribute('aria-pressed', 'true')
  })

  it('forwards its ref and works as a Popover trigger', async () => {
    const ref = createRef<HTMLButtonElement>()
    render(
      <Popover>
        <PopoverTrigger asChild>
          <FilterButton ref={ref} label="Filter by property" />
        </PopoverTrigger>
        <PopoverContent>property picker</PopoverContent>
      </Popover>
    )
    expect(ref.current).toBeInstanceOf(HTMLButtonElement)
    expect(screen.queryByText('property picker')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Filter by property' }))
    expect(screen.getByText('property picker')).toBeInTheDocument()
    expect(ref.current).toHaveAttribute('aria-expanded', 'true')
  })

  it('shows a tooltip on keyboard focus', async () => {
    render(<FilterButton />)
    await userEvent.tab()
    expect(screen.getByRole('button', { name: 'Filters' })).toHaveFocus()
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Filters')
  })
})

describe('FilterPanelToggle', () => {
  it('renders the panel toggle and the sheet trigger, wired to their handlers', () => {
    const onToggle = vi.fn()
    const onOpenSheet = vi.fn()
    render(
      <FilterPanelToggle
        open={false}
        onToggle={onToggle}
        onOpenSheet={onOpenSheet}
        activeCount={2}
        controlsId="x-filters"
      />
    )
    const [panel, sheet] = screen.getAllByRole('button', { name: 'Filters, 2 active' })
    // Closed: the panel is not in the page, so nothing to point at.
    expect(panel).not.toHaveAttribute('aria-controls')
    expect(panel).toHaveAttribute('aria-pressed', 'false')
    expect(sheet).toHaveAttribute('aria-haspopup', 'dialog')
    fireEvent.click(panel)
    fireEvent.click(sheet)
    expect(onToggle).toHaveBeenCalledOnce()
    expect(onOpenSheet).toHaveBeenCalledOnce()
  })

  it('points at the panel while it is open and keeps the filter icon', () => {
    render(
      <FilterPanelToggle
        open
        onToggle={() => {}}
        onOpenSheet={() => {}}
        activeCount={0}
        controlsId="x-filters"
      />
    )
    const [panel] = screen.getAllByRole('button', { name: 'Filters' })
    expect(panel).toHaveAttribute('aria-controls', 'x-filters')
    expect(panel).toHaveAttribute('aria-pressed', 'true')
    expect(panel).toHaveClass('bg-accent')
    expect(panel.querySelector('svg')).toHaveClass('lucide-list-filter')
  })
})

describe('FilterPanelToggle sheetOnly (the list has Add filter)', () => {
  it('drops the desktop panel toggle and keeps the sheet trigger on a phone only', () => {
    const onOpenSheet = vi.fn()
    render(
      <FilterPanelToggle
        open={false}
        onToggle={() => {}}
        onOpenSheet={onOpenSheet}
        activeCount={0}
        controlsId="x-filters"
        sheetOnly
      />
    )
    const buttons = screen.getAllByRole('button', { name: 'Filters' })
    expect(buttons).toHaveLength(1)
    // From 768 Add filter is the one entry: this trigger is a phone's.
    expect(buttons[0]).toHaveClass('md:hidden')
    expect(buttons[0]).not.toHaveAttribute('aria-pressed')
    fireEvent.click(buttons[0])
    expect(onOpenSheet).toHaveBeenCalledOnce()
  })

  it('Add filter shows from 768 only (a phone has the joined Filters button)', () => {
    render(<AddFilterButton />)
    expect(screen.getByRole('button', { name: 'Add filter' })).toHaveClass(
      'hidden',
      'md:inline-flex'
    )
  })

  it('Add filter ends with a row that opens the panel', () => {
    const onClick = vi.fn()
    render(<ShowFilterPanelButton onClick={onClick} />)
    fireEvent.click(screen.getByRole('button', { name: 'Show the filter panel' }))
    expect(onClick).toHaveBeenCalledOnce()
  })
})

describe('useAddFilterShortcut', () => {
  function Probe({ onOpen, enabled }: { onOpen: () => void; enabled?: boolean }) {
    useAddFilterShortcut(onOpen, enabled)
    return (
      <div>
        <p data-testid="outside">list</p>
        <input aria-label="field" />
        <div role="menu">
          <button type="button">item</button>
        </div>
      </div>
    )
  }
  const press = (el: Element, init: KeyboardEventInit = {}) =>
    fireEvent.keyDown(el, { key: 'f', ...init })

  it('opens on f pressed outside a field, a menu or a dialog', () => {
    const onOpen = vi.fn()
    render(<Probe onOpen={onOpen} />)
    press(screen.getByTestId('outside'))
    expect(onOpen).toHaveBeenCalledOnce()
    press(screen.getByRole('textbox', { name: 'field' }))
    press(screen.getByRole('button', { name: 'item' }))
    fireEvent.keyDown(screen.getByTestId('outside'), { key: 'g' })
    expect(onOpen).toHaveBeenCalledOnce()
  })

  it('leaves the key to the browser with a modifier', () => {
    const onOpen = vi.fn()
    render(<Probe onOpen={onOpen} />)
    press(screen.getByTestId('outside'), { ctrlKey: true })
    press(screen.getByTestId('outside'), { metaKey: true })
    press(screen.getByTestId('outside'), { altKey: true })
    expect(onOpen).not.toHaveBeenCalled()
  })

  it('does nothing while a modal is open', () => {
    const onOpen = vi.fn()
    render(
      <>
        <Probe onOpen={onOpen} />
        <div role="dialog" data-state="open" />
      </>
    )
    press(screen.getByTestId('outside'))
    expect(onOpen).not.toHaveBeenCalled()
  })

  it('is off in Query mode: disabled by the caller, or the toolbar tokens are inert', () => {
    const onOpen = vi.fn()
    const view = render(<Probe onOpen={onOpen} enabled={false} />)
    press(screen.getByTestId('outside'))
    expect(onOpen).not.toHaveBeenCalled()
    view.rerender(
      <>
        <Probe onOpen={onOpen} />
        <div data-slot="list-toolbar-tokens" inert />
      </>
    )
    press(screen.getByTestId('outside'))
    expect(onOpen).not.toHaveBeenCalled()
  })

  it('calls the latest callback and stops listening once its list is gone', () => {
    const first = vi.fn()
    const second = vi.fn()
    const view = render(<Probe onOpen={first} />)
    view.rerender(<Probe onOpen={second} />)
    press(screen.getByTestId('outside'))
    expect(first).not.toHaveBeenCalled()
    expect(second).toHaveBeenCalledOnce()
    view.unmount()
    press(document.body)
    expect(second).toHaveBeenCalledOnce()
  })
})

describe('FilterSheet', () => {
  it('shows the panel under its own title and closes from the footer', async () => {
    const onOpenChange = vi.fn()
    render(
      <FilterSheet open onOpenChange={onOpenChange} title="Task filters" resultLabel="Show 3 tasks">
        <p>panel</p>
      </FilterSheet>
    )
    expect(screen.getByRole('dialog', { name: 'Task filters' })).toBeInTheDocument()
    expect(screen.getByText('panel')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Show 3 tasks' }))
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })
})
