import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useState } from 'react'
import { act, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ListToolbar } from '../list-toolbar'
import { ListSearch } from '../list-search'
import { FilterButton, FilterPanelToggle } from '../filter-button'
import { OverflowChips } from '../overflow-chips'
import { useSearchQuery, SEARCH_DEBOUNCE_MS } from '@/hooks/use-search-query'

// Radix Tooltip measures its content; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

/** A controlled search, as every list wires it. */
function Search({
  initial = '',
  filter,
  onTerm,
}: {
  initial?: string
  filter?: React.ReactNode
  onTerm?: (term: string) => void
}) {
  const [value, setValue] = useState(initial)
  const { term } = useSearchQuery(value)
  onTerm?.(term)
  return (
    <ListToolbar
      search={{
        value,
        onChange: setValue,
        placeholder: 'Search name, host or tool…',
        label: 'Search sensors',
      }}
      filter={filter}
      start={<button type="button">Status: Online</button>}
      end={<button type="button">View</button>}
    />
  )
}

function names(root: HTMLElement) {
  return [...root.querySelectorAll('button, input')].map(
    (el) => el.getAttribute('aria-label') || el.textContent
  )
}

describe('ListToolbar slots', () => {
  it('orders filter trigger, search, filter tokens, then the end group pushed to the far side', () => {
    render(<Search filter={<FilterButton activeCount={2} />} />)
    const bar = screen.getByTestId('data-table-toolbar')
    expect(bar).toHaveAttribute('data-slot', 'list-toolbar')
    expect(names(bar)).toEqual(['Filters (2 active)', 'Search sensors', 'Status: Online', 'View'])
    expect(screen.getByText('View').parentElement).toHaveClass('ms-auto')
  })

  it('joins the filter trigger to the start of the search field (one control, no gap)', () => {
    render(<Search filter={<FilterButton />} />)
    const group = document.querySelector('[data-slot="list-search"]') as HTMLElement
    const trigger = screen.getByRole('button', { name: 'Filters' })
    expect(group.contains(trigger)).toBe(true)
    expect(group.className).toContain('[&_[data-slot=filter-button]]:rounded-e-none')
    expect(screen.getByRole('searchbox', { name: 'Search sensors' })).toHaveClass('rounded-s-none')
    // The field overlaps the trigger's border by one pixel: no gap, no double border.
    expect(screen.getByRole('searchbox').parentElement).toHaveClass('-ms-px')
  })

  it('draws the trigger alone in the search place when the list has no search', () => {
    render(<ListToolbar filter={<FilterButton />} end={<button type="button">View</button>} />)
    const start = document.querySelector('[data-slot="list-toolbar-start"]') as HTMLElement
    expect(start.firstElementChild).toBe(screen.getByRole('button', { name: 'Filters' }))
    expect(document.querySelector('[data-slot="list-search"]')).toBeNull()
  })

  it('renders no empty groups and no chips row when nothing is passed', () => {
    render(<ListToolbar end={<button type="button">View</button>} />)
    const bar = screen.getByTestId('data-table-toolbar')
    expect(bar.children).toHaveLength(1)
    expect(screen.queryByTestId('data-table-toolbar-below')).toBeNull()
  })

  it('puts the chips in their own full-width row 8px under the toolbar', () => {
    render(<ListToolbar end={<button type="button">View</button>} below={<span>chip</span>} />)
    const region = document.querySelector('[data-slot="list-toolbar-region"]') as HTMLElement
    expect(region).toHaveClass('flex-col', 'gap-2')
    const below = screen.getByTestId('data-table-toolbar-below')
    expect(below).toHaveTextContent('chip')
    expect(region.firstElementChild).toBe(screen.getByTestId('data-table-toolbar'))
  })
})

describe('ListSearch', () => {
  it('is a 36px search box with the icon, a placeholder and its own accessible name', () => {
    render(<Search />)
    const box = screen.getByRole('searchbox', { name: 'Search sensors' })
    expect(box).toHaveAttribute('placeholder', 'Search name, host or tool…')
    expect(box).toHaveClass('h-9', 'ps-9')
    expect(box).toHaveAttribute('aria-keyshortcuts', '/')
    expect(box.parentElement?.querySelector('svg')).not.toBeNull()
  })

  it('shows a clear button only while there is text, and clearing refocuses the field', async () => {
    const user = userEvent.setup()
    render(<Search />)
    expect(screen.queryByRole('button', { name: 'Clear search' })).toBeNull()
    await user.type(screen.getByRole('searchbox'), 'edge')
    await user.click(screen.getByRole('button', { name: 'Clear search' }))
    expect(screen.getByRole('searchbox')).toHaveValue('')
    expect(screen.getByRole('searchbox')).toHaveFocus()
  })

  it('clears on Escape', async () => {
    const user = userEvent.setup()
    render(<Search />)
    await user.type(screen.getByRole('searchbox'), 'edge')
    await user.keyboard('{Escape}')
    expect(screen.getByRole('searchbox')).toHaveValue('')
  })

  it('uses the label as the placeholder fallback for its name', () => {
    render(<ListSearch value="" onChange={() => {}} placeholder="Search rules…" />)
    expect(screen.getByRole('searchbox', { name: 'Search rules…' })).toBeInTheDocument()
  })
})

describe('debounce (the request term)', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('sends the term once typing pauses for 300 ms, never per keystroke', () => {
    const terms: string[] = []
    render(<Search onTerm={(t) => terms.push(t)} />)
    const box = screen.getByRole('searchbox')
    fireEvent.change(box, { target: { value: 'ed' } })
    fireEvent.change(box, { target: { value: 'edg' } })
    fireEvent.change(box, { target: { value: 'edge' } })
    act(() => vi.advanceTimersByTime(SEARCH_DEBOUNCE_MS - 1))
    expect(terms.at(-1)).toBe('')
    act(() => vi.advanceTimersByTime(1))
    expect(terms.at(-1)).toBe('edge')
    expect(new Set(terms)).toEqual(new Set(['', 'edge']))
  })
})

describe('keyboard', () => {
  it('"/" focuses the search box of the first toolbar on the page', () => {
    render(
      <>
        <Search />
        <ListToolbar search={{ value: '', onChange: () => {}, placeholder: 'Search other…' }} />
      </>
    )
    fireEvent.keyDown(document.body, { key: '/' })
    expect(screen.getByRole('searchbox', { name: 'Search sensors' })).toHaveFocus()
  })

  it('"/" types normally inside a text field', () => {
    render(
      <>
        <input aria-label="Note" />
        <Search />
      </>
    )
    const note = screen.getByRole('textbox', { name: 'Note' })
    note.focus()
    const ev = fireEvent.keyDown(note, { key: '/' })
    expect(ev).toBe(true) // not prevented
    expect(note).toHaveFocus()
  })

  it('"/" with a modifier is left alone', () => {
    render(<Search />)
    fireEvent.keyDown(document.body, { key: '/', ctrlKey: true })
    expect(screen.getByRole('searchbox')).not.toHaveFocus()
  })

  it('"f" opens the filters through the trigger', () => {
    const onToggle = vi.fn()
    render(
      <Search
        filter={
          <FilterPanelToggle
            open={false}
            onToggle={onToggle}
            onOpenSheet={() => {}}
            activeCount={0}
            controlsId="p"
          />
        }
      />
    )
    fireEvent.keyDown(document.body, { key: 'f' })
    expect(onToggle).toHaveBeenCalledTimes(1)
  })

  it('"f" is left to "Add filter" on a list that has one', () => {
    const onClick = vi.fn()
    render(
      <>
        <Search filter={<FilterButton onClick={onClick} />} />
        <button type="button" aria-keyshortcuts="f">
          Add filter
        </button>
      </>
    )
    fireEvent.keyDown(document.body, { key: 'f' })
    expect(onClick).not.toHaveBeenCalled()
  })
})

describe('OverflowChips', () => {
  const chips = (n: number) => Array.from({ length: n }, (_, i) => <li key={i}>chip {i + 1}</li>)

  it('shows every chip up to the cap', () => {
    render(<OverflowChips max={3}>{chips(3)}</OverflowChips>)
    expect(screen.getAllByRole('listitem')).toHaveLength(3)
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('folds the rest behind "+N" and expands and folds again', async () => {
    const user = userEvent.setup()
    render(
      <OverflowChips max={3} label="Filters">
        {chips(5)}
      </OverflowChips>
    )
    expect(screen.getByRole('list', { name: 'Filters' })).toBeInTheDocument()
    expect(screen.queryByText('chip 4')).toBeNull()
    const more = screen.getByRole('button', { name: 'Show 2 more filters' })
    expect(more).toHaveTextContent('+2')
    await user.click(more)
    expect(screen.getByText('chip 5')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Show fewer' }))
    expect(screen.queryByText('chip 5')).toBeNull()
  })

  it('renders nothing without chips', () => {
    const { container } = render(<OverflowChips>{[]}</OverflowChips>)
    expect(container).toBeEmptyDOMElement()
  })
})
