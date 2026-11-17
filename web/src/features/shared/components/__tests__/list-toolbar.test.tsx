import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useState } from 'react'
import { act, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ListToolbar } from '../list-toolbar'
import { ListSearch, ListSearchModeSwitch } from '../list-search'
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

  it('keeps four round corners while the passed trigger is not drawn at this width', () => {
    // jsdom draws nothing (no client rects): a trigger hidden by a breakpoint.
    render(<Search filter={<FilterButton />} />)
    const group = document.querySelector('[data-slot="list-search"]') as HTMLElement
    expect(group).not.toHaveAttribute('data-joined')
    expect(screen.getByRole('searchbox', { name: 'Search sensors' })).not.toHaveClass(
      'rounded-s-none'
    )
    expect(screen.getByRole('searchbox').parentElement).not.toHaveClass('-ms-px')
  })

  it('joins the filter trigger to the start of the search field (one control, no gap)', () => {
    // The trigger is drawn: it has a box.
    const rects = vi.spyOn(HTMLElement.prototype, 'getClientRects').mockImplementation(function (
      this: HTMLElement
    ) {
      const drawn = this.dataset.slot === 'filter-button'
      return (drawn ? [{ width: 32, height: 32 }] : []) as unknown as DOMRectList
    })
    render(<Search filter={<FilterButton />} />)
    rects.mockRestore()
    expect(document.querySelector('[data-slot="list-search"]')).toHaveAttribute('data-joined')
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
    // Basis 0: the chips take the room the actions leave, never a line of their own.
    expect(screen.getByTestId('data-table-toolbar-below').className).toContain(
      '@max-md/toolbar:flex-[1_1_0%]'
    )
    expect(screen.getByTestId('data-table-toolbar-below').className).not.toContain('basis-auto')
  })

  it('on a phone is two lines: the search alone, then tokens scrolling beside the pinned actions', () => {
    render(
      <ListToolbar
        search={{ value: '', onChange: () => {}, placeholder: 'Search things' }}
        start={<button type="button">Status: Open</button>}
        end={<button type="button">Refresh</button>}
      />
    )
    const lead = document.querySelector('[data-slot="list-toolbar-lead"]') as HTMLElement
    expect(lead.className).toContain('@max-md/toolbar:basis-full')
    const startGroup = document.querySelector('[data-slot="list-toolbar-start"]') as HTMLElement
    expect(startGroup.className).toContain('@max-md/toolbar:contents')
    const tokens = document.querySelector('[data-slot="list-toolbar-tokens"]') as HTMLElement
    // One scrolling strip with the edge fade, never a wrap.
    expect(tokens.className).toContain('@max-md/toolbar:overflow-x-auto')
    expect(tokens.className).toContain('@max-md/toolbar:flex-nowrap')
    expect(tokens.className).toContain('data-[fade-end=true]')
    expect(tokens).toHaveTextContent('Status: Open')
    const end = document.querySelector('[data-slot="list-toolbar-end"]') as HTMLElement
    expect(end.className).toContain('@max-md/toolbar:flex-nowrap')
    // Desktop: the wrappers draw no box, the row is as before.
    expect(lead.className).toMatch(/(^|\s)contents(\s|$)/)
    expect(tokens.className).toMatch(/(^|\s)contents(\s|$)/)
  })

  it('on a phone with a chips row pins the tokens (Add filter) after the chips, beside the actions', () => {
    render(
      <ListToolbar
        search={{ value: '', onChange: () => {}, placeholder: 'Search things' }}
        start={<button type="button">Add filter</button>}
        end={<button type="button">Views</button>}
        below={<span>chip</span>}
      />
    )
    const tokens = document.querySelector('[data-slot="list-toolbar-tokens"]') as HTMLElement
    expect(tokens.className).toContain('@max-md/toolbar:order-last')
    // Capped, so the chips keep room; it scrolls past that.
    expect(tokens.className).toContain('@max-md/toolbar:max-w-[60%]')
    expect(tokens.className).toContain('@max-md/toolbar:overflow-x-auto')
  })

  it('has the same boxes with and without a chips row, so the first chip moves nothing', () => {
    const classes = () => {
      const q = (slot: string) =>
        (document.querySelector(`[data-slot="${slot}"]`) as HTMLElement).className
      return {
        region: q('list-toolbar-region'),
        toolbar: q('list-toolbar'),
        tokens: q('list-toolbar-tokens'),
        end: q('list-toolbar-end'),
      }
    }
    const props = {
      search: { value: '', onChange: () => {}, placeholder: 'Search things' },
      start: <button type="button">Status: Open</button>,
      end: <button type="button">Views</button>,
    }
    const { rerender } = render(<ListToolbar {...props} />)
    const without = classes()
    rerender(<ListToolbar {...props} below={<span>chip</span>} />)
    expect(classes()).toEqual(without)
    // The region is the size container in both.
    expect(without.region).toMatch(/@container\/toolbar/)
    expect(without.toolbar).not.toMatch(/(^|\s)@container\/toolbar/)
  })

  it('on a phone anchors the tokens to the end of line 2, the chips own its start', () => {
    render(
      <ListToolbar
        search={{ value: '', onChange: () => {}, placeholder: 'Search things' }}
        start={<button type="button">Status: Open</button>}
        end={<button type="button">Views</button>}
      />
    )
    const tokens = document.querySelector('[data-slot="list-toolbar-tokens"]') as HTMLElement
    // After the chips (order-last), pushed to the end while there is no chip.
    expect(tokens.className).toContain('@max-md/toolbar:order-last')
    expect(tokens.className).toContain('@max-md/toolbar:ms-auto')
    expect(tokens.className).not.toContain('@max-md/toolbar:flex-[1_1_0%]')
    // Never shrinks: its width does not depend on the chips beside it.
    expect(tokens.className).toContain('@max-md/toolbar:flex-[0_0_auto]')
    const end = document.querySelector('[data-slot="list-toolbar-end"]') as HTMLElement
    expect(end.className).toContain('@max-md/toolbar:order-last')
  })

  it('passes its className to the outer region', () => {
    render(<ListToolbar end={<button type="button">View</button>} className="mt-3" />)
    expect(document.querySelector('[data-slot="list-toolbar-region"]')).toHaveClass('mt-3')
  })
})

describe('ListSearch', () => {
  it('is a search box at the field height with the icon, a placeholder and its own accessible name', () => {
    render(<Search />)
    const box = screen.getByRole('searchbox', { name: 'Search sensors' })
    expect(box).toHaveAttribute('placeholder', 'Search name, host or tool…')
    expect(box).toHaveClass('h-control-field', 'ps-9')
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

  it('draws the Basic | Query switch as its own control before the field', async () => {
    const onActiveChange = vi.fn()
    const { container } = render(
      <ListSearch
        value=""
        onChange={() => {}}
        placeholder="Search findings…"
        filter={<button type="button">Filters</button>}
        query={{
          active: false,
          onActiveChange,
          renderEditor: () => null,
        }}
      />
    )
    const field = container.querySelector('[data-slot="list-search"]') as HTMLElement
    const switches = container.querySelectorAll('[data-slot="list-search-mode"]')
    // The segmented switch (from 768) and the phone toggle: both outside the
    // field, both before it, and before the joined filter trigger.
    expect(switches).toHaveLength(2)
    for (const sw of switches) {
      expect(field.contains(sw)).toBe(false)
      expect(sw.compareDocumentPosition(field) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    }
    expect(field.firstElementChild).toHaveTextContent('Filters')
    // The field's end keeps only its own controls.
    const end = container.querySelector('[data-slot="list-search-end"]') as HTMLElement
    expect(end.querySelector('button')).toBeNull()
    // Keyboard operable, named, the pressed state follows the mode.
    expect(screen.getByRole('group', { name: 'Search mode' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Basic' })).toHaveAttribute('aria-pressed', 'true')
    await userEvent.tab()
    await userEvent.tab()
    expect(screen.getByRole('button', { name: 'Query' })).toHaveFocus()
    await userEvent.keyboard('{Enter}')
    expect(onActiveChange).toHaveBeenCalledWith(true)
    await userEvent.click(screen.getByRole('button', { name: 'Query mode' }))
    expect(onActiveChange).toHaveBeenLastCalledWith(true)
  })

  it('keeps the same end room in Query mode whatever the editor draws', () => {
    const { container, rerender } = render(
      <ListSearch
        value=""
        onChange={() => {}}
        placeholder="Search findings…"
        query={{ active: false, onActiveChange: () => {}, renderEditor: () => null }}
      />
    )
    const basic = container.querySelector<HTMLElement>('[data-slot="list-search-field"]')!
    expect(basic.style.getPropertyValue('--list-search-end')).toBe('2.25rem')
    rerender(
      <ListSearch
        value=""
        onChange={() => {}}
        placeholder="Search findings…"
        query={{
          active: true,
          onActiveChange: () => {},
          renderEditor: ({ adornments }) => <div data-testid="editor">{adornments}</div>,
        }}
      />
    )
    const q = container.querySelector<HTMLElement>('[data-slot="list-search-query"]')!
    expect(q.style.getPropertyValue('--list-search-end')).toBe('0.5rem')
    // The field's size classes do not change with the mode.
    expect(container.querySelector('[data-slot="list-search"]')!.className).not.toMatch(/max-w-xl/)
  })

  it('holds its Basic width in Query mode, so the tokens leaving move nothing', () => {
    const rect = HTMLElement.prototype.getBoundingClientRect
    HTMLElement.prototype.getBoundingClientRect = function (this: HTMLElement) {
      const width = this.dataset.slot === 'list-search' ? 333 : 0
      return { width, height: 32, top: 0, left: 0, right: width, bottom: 32, x: 0, y: 0 } as DOMRect
    }
    try {
      const props = (active: boolean) => ({
        value: '',
        onChange: () => {},
        placeholder: 'Search findings…',
        query: { active, onActiveChange: () => {}, renderEditor: () => null },
      })
      const { container, rerender } = render(<ListSearch {...props(false)} />)
      const field = () => container.querySelector('[data-slot="list-search"]') as HTMLElement
      expect(field().style.width).toBe('')
      rerender(<ListSearch {...props(true)} />)
      expect(field().style.width).toBe('333px')
      expect(field().style.flex).toMatch(/none|0 0 auto/)
      rerender(<ListSearch {...props(false)} />)
      expect(field().style.width).toBe('')
    } finally {
      HTMLElement.prototype.getBoundingClientRect = rect
    }
  })

  it('the switch alone reports the mode; Ctrl+/ switches from anywhere', async () => {
    const onModeChange = vi.fn()
    render(<ListSearchModeSwitch mode="query" onModeChange={onModeChange} />)
    expect(screen.getByRole('button', { name: 'Query' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: 'Query mode' })).toHaveAttribute(
      'aria-pressed',
      'true'
    )
    await userEvent.click(screen.getByRole('button', { name: 'Basic' }))
    expect(onModeChange).toHaveBeenCalledWith('basic')
    const onActiveChange = vi.fn()
    render(
      <ListSearch
        value=""
        onChange={() => {}}
        placeholder="Search findings…"
        query={{ active: true, onActiveChange, renderEditor: () => null }}
      />
    )
    fireEvent.keyDown(window, { key: '/', ctrlKey: true })
    expect(onActiveChange).toHaveBeenCalledWith(false)
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

  it('keeps one line with fixed places: locked chip, chips, actions at the end, no count', () => {
    render(
      <FilterChipsRow
        leading={<LockedChip>Hiding names not ours</LockedChip>}
        chips={chips(2)}
        trailing={<button type="button">Add filter</button>}
      />
    )
    const row = document.querySelector('[data-slot="filter-chips-row"]') as HTMLElement
    // Clipped, not hidden: an overflow-hidden box can still be scrolled sideways.
    expect(row).toHaveClass('flex-nowrap', 'overflow-clip')
    expect(row).not.toHaveClass('overflow-hidden')
    expect(row.textContent).toBe('Hiding names not ourschip 1chip 2Add filter')
    // The count is said once, in the list's title row, never here.
    expect(row.querySelector('[data-slot="list-count"]')).toBeNull()
    expect(screen.getByText('Add filter').closest('[data-slot="filter-chips-end"]')).toHaveClass(
      'ms-auto',
      'shrink-0'
    )
    expect(screen.getByRole('list', { name: 'Active filters' }).children).toHaveLength(2)
  })

  it('draws Clear filters last, after the trailing actions, when the list can clear', async () => {
    const onClearAll = vi.fn()
    render(
      <FilterChipsRow
        chips={chips(2)}
        trailing={<button type="button">Reset to view</button>}
        onClearAll={onClearAll}
      />
    )
    const trail = document.querySelector('[data-slot="filter-chips-trailing"]') as HTMLElement
    expect([...trail.querySelectorAll('button')].map((b) => b.textContent)).toEqual([
      'Reset to view',
      'Clear filters',
    ])
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(onClearAll).toHaveBeenCalledOnce()
  })

  it('draws no Clear filters without onClearAll', () => {
    render(<FilterChipsRow chips={chips(2)} />)
    expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull()
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
