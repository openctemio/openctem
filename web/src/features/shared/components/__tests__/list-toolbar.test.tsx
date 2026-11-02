import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useState } from 'react'
import { act, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ListToolbar } from '../list-toolbar'
import { ListSearch } from '../list-search'
import { FilterButton, FilterPanelToggle } from '../filter-button'
import { FilterChipsRow, LockedChip } from '../filter-chips-row'
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
    expect(region).toHaveClass('flex', 'flex-wrap', 'gap-2')
    const below = screen.getByTestId('data-table-toolbar-below')
    expect(below).toHaveTextContent('chip')
    expect(below).toHaveClass('basis-full')
    expect(region.firstElementChild).toBe(screen.getByTestId('data-table-toolbar'))
    expect(screen.getByTestId('data-table-toolbar')).toHaveClass('basis-full')
  })

  it('on a phone lends the toolbar to the region so the end group joins the chips row', () => {
    render(<ListToolbar end={<button type="button">View</button>} below={<span>chip</span>} />)
    const region = document.querySelector('[data-slot="list-toolbar-region"]') as HTMLElement
    // The region answers the toolbar's container queries once the toolbar box is lent out.
    expect(region.className).toMatch(/@container\/toolbar/)
    const bar = screen.getByTestId('data-table-toolbar')
    expect(bar.className).toContain('@max-md/toolbar:contents')
    // Not a container itself: a box-less container would answer no query.
    expect(bar.className).not.toMatch(/(^|\s)@container\/toolbar/)
    const end = document.querySelector('[data-slot="list-toolbar-end"]') as HTMLElement
    expect(end.className).toContain('@max-md/toolbar:order-last')
    expect(screen.getByTestId('data-table-toolbar-below').className).toContain(
      '@max-md/toolbar:basis-auto'
    )
  })

  it('without a chips row keeps the toolbar a box of its own', () => {
    render(<ListToolbar end={<button type="button">View</button>} />)
    expect(screen.getByTestId('data-table-toolbar').className).not.toContain('contents')
    expect(screen.getByTestId('data-table-toolbar').className).toMatch(/@container\/toolbar/)
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

describe('FilterChipsRow', () => {
  const chips = (n: number) =>
    Array.from({ length: n }, (_, i) => <span key={`c${i}`}>chip {i + 1}</span>)

  /** Give the row and every chip a width (jsdom does not lay out). */
  function layout(rowWidth: number, chipWidth: number) {
    vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockImplementation(function (
      this: HTMLElement
    ) {
      return this.dataset.slot === 'filter-chips-row' ? rowWidth : 0
    })
    vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockImplementation(function (
      this: HTMLElement
    ) {
      return this.dataset.chipKey ? chipWidth : 0
    })
  }
  afterEach(() => vi.restoreAllMocks())

  it('keeps one line with fixed places: locked chip, chips, trailing, count at the end', () => {
    render(
      <FilterChipsRow
        leading={<LockedChip>Hiding names not ours</LockedChip>}
        chips={chips(2)}
        trailing={<button type="button">Add filter</button>}
        end={<span>361 assets</span>}
      />
    )
    const row = document.querySelector('[data-slot="filter-chips-row"]') as HTMLElement
    expect(row).toHaveClass('flex-nowrap', 'overflow-hidden')
    expect(row.textContent).toBe('Hiding names not ourschip 1chip 2Add filter361 assets')
    expect(screen.getByText('361 assets').parentElement).toHaveClass('ms-auto', 'shrink-0')
    expect(screen.getByRole('list', { name: 'Active filters' }).children).toHaveLength(2)
  })

  it('shows every chip when they fit (or nothing can be measured)', () => {
    render(<FilterChipsRow chips={chips(5)} />)
    expect(screen.getAllByRole('listitem')).toHaveLength(5)
    expect(screen.queryByRole('button', { name: /more/ })).toBeNull()
  })

  it('folds the chips that do not fit into "+N more", listed and still usable in a popover', async () => {
    layout(400, 100)
    const user = userEvent.setup()
    render(<FilterChipsRow chips={chips(6)} />)
    // 400 - 88 (room for "+N more") leaves room for 2 chips of 100 + gap.
    expect(screen.getByRole('list', { name: 'Active filters' }).children).toHaveLength(2)
    const more = screen.getByRole('button', { name: '+4 more' })
    await user.click(more)
    const extra = await screen.findByRole('list', { name: 'More filters' })
    expect(extra.children).toHaveLength(4)
    expect(extra).toHaveTextContent('chip 6')
  })
})

describe('LockedChip', () => {
  it('is a quiet, non-removable chip with a lock and an optional action', async () => {
    const onShow = vi.fn()
    const user = userEvent.setup()
    render(
      <LockedChip actionLabel="Show" onAction={onShow}>
        Hiding names awaiting review
      </LockedChip>
    )
    const chip = document.querySelector('[data-slot="locked-chip"]') as HTMLElement
    expect(chip).toHaveClass('border-dashed', 'text-muted-foreground')
    expect(chip.querySelector('svg.lucide-lock')).not.toBeNull()
    expect(screen.queryByRole('button', { name: /remove/i })).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Show' }))
    expect(onShow).toHaveBeenCalledOnce()
  })
})
