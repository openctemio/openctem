import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useState } from 'react'
import { act, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ListToolbar } from '../list-toolbar'
import { ListSearch, ListSearchModeSwitch } from '../list-search'
import { FilterButton, FilterPanelToggle } from '../filter-button'
import { FilterChipsRow, LockedChip } from '../filter-chips-row'
import { FilterSheet } from '../filter-sheet'
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
    expect(names(bar)).toEqual(['Filters, 2 active', 'Search sensors', 'Status: Online', 'View'])
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
    const lead = start.firstElementChild as HTMLElement
    expect(lead).toHaveAttribute('data-slot', 'list-toolbar-lead')
    // No box of its own on a desktop: the trigger is the first control.
    expect(lead).toHaveClass('contents')
    expect(lead.firstElementChild).toBe(screen.getByRole('button', { name: 'Filters' }))
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
    const layout = document.querySelector('[data-slot="list-toolbar-layout"]') as HTMLElement
    expect(layout).toHaveClass('flex', 'flex-wrap', 'gap-2')
    expect(layout.parentElement).toHaveAttribute('data-slot', 'list-toolbar-region')
    const below = screen.getByTestId('data-table-toolbar-below')
    expect(below).toHaveTextContent('chip')
    expect(below).toHaveClass('basis-full')
    expect(layout.firstElementChild).toBe(screen.getByTestId('data-table-toolbar'))
    expect(screen.getByTestId('data-table-toolbar')).toHaveClass('basis-full')
  })

  it('on a phone lends the toolbar to a grid inside the region (the container)', () => {
    render(<ListToolbar end={<button type="button">View</button>} below={<span>chip</span>} />)
    const region = document.querySelector('[data-slot="list-toolbar-region"]') as HTMLElement
    // The region answers the toolbar's container queries once the toolbar box
    // is lent out; a query never styles the container, so the grid is inside.
    expect(region.className).toMatch(/@container\/toolbar/)
    expect(region.className).not.toContain('@max-md/toolbar:grid')
    const layout = document.querySelector('[data-slot="list-toolbar-layout"]') as HTMLElement
    expect(layout.className).toContain('@max-md/toolbar:grid')
    expect(layout.className).toContain('@max-md/toolbar:grid-cols-[auto_minmax(0,1fr)_auto]')
    // No grid gaps: a line that draws nothing takes no room.
    expect(layout.className).toContain('@max-md/toolbar:gap-0')
    const bar = screen.getByTestId('data-table-toolbar')
    expect(bar.className).toContain('@max-md/toolbar:contents')
    // Not a container itself: a box-less container would answer no query.
    expect(bar.className).not.toMatch(/(^|\s)@container\/toolbar/)
    // No tokens: the chips own the whole second line.
    const below = screen.getByTestId('data-table-toolbar-below')
    expect(below.className).toContain('@max-md/toolbar:row-start-2')
    expect(below.className).toContain('@max-md/toolbar:col-end-4')
  })

  it('on a phone puts the end actions on the search line, so Views never sits on a line alone', () => {
    render(
      <ListToolbar
        search={{ value: '', onChange: () => {}, placeholder: 'Search things' }}
        start={<button type="button">Status: Open</button>}
        end={<button type="button">Views</button>}
      />
    )
    const lead = document.querySelector('[data-slot="list-toolbar-lead"]') as HTMLElement
    expect(lead.className).toContain('@max-md/toolbar:row-start-1')
    expect(lead.className).toContain('@max-md/toolbar:col-start-1')
    expect(lead.className).toContain('@max-md/toolbar:col-end-3')
    const end = document.querySelector('[data-slot="list-toolbar-end"]') as HTMLElement
    expect(end.className).toContain('@max-md/toolbar:row-start-1')
    expect(end.className).toContain('@max-md/toolbar:col-start-3')
    // The search keeps at least 12rem; wider actions wrap inside their group.
    expect(end.className).toContain('@max-md/toolbar:max-w-[calc(100cqw-12rem)]')
    expect(end.className).toContain('flex-wrap')
    expect(end.className).not.toContain('order-last')
    const startGroup = document.querySelector('[data-slot="list-toolbar-start"]') as HTMLElement
    expect(startGroup.className).toContain('@max-md/toolbar:contents')
    // Desktop: the wrappers draw no box, the row is as before.
    expect(lead.className).toMatch(/(^|\s)contents(\s|$)/)
  })

  it('on a phone in Query mode gives the field the whole line: the end actions step down, the inert tokens go, the chips start line 3', () => {
    render(
      <ListToolbar
        search={{
          value: '',
          onChange: () => {},
          placeholder: 'Search things',
          query: { active: true, onActiveChange: () => {}, renderEditor: () => null },
        }}
        start={<button type="button">Status: Open</button>}
        end={<button type="button">Views</button>}
        below={<span>Hiding 8 names</span>}
      />
    )
    // The chips never share line 2 with the end actions stepped down there.
    const below = screen.getByTestId('data-table-toolbar-below')
    expect(below.className).toContain('@max-md/toolbar:row-start-3')
    expect(below.className).not.toMatch(/(^|\s)@max-md\/toolbar:row-start-2(\s|$)/)
    const lead = document.querySelector('[data-slot="list-toolbar-lead"]') as HTMLElement
    expect(lead.className).toContain('@max-md/toolbar:col-end-4')
    expect(lead.className).not.toContain('@max-md/toolbar:col-end-3')
    const end = document.querySelector('[data-slot="list-toolbar-end"]') as HTMLElement
    expect(end.className).toContain('@max-md/toolbar:row-start-2')
    expect(end.className).not.toContain('@max-md/toolbar:row-start-1')
    const tokens = document.querySelector('[data-slot="list-toolbar-tokens"]') as HTMLElement
    expect(tokens.className).toMatch(/(^|\s)hidden(\s|$)/)
  })

  it('in Query mode at any width the tokens step aside and the field takes the row up to the end group', () => {
    const props = (active: boolean) => ({
      value: '',
      onChange: () => {},
      placeholder: 'Search things',
      query: { active, onActiveChange: () => {}, renderEditor: () => null },
    })
    const { rerender } = render(
      <ListToolbar
        search={props(false)}
        start={<button type="button">Status: Open</button>}
        end={<button type="button">Views</button>}
      />
    )
    const tokens = () => document.querySelector('[data-slot="list-toolbar-tokens"]') as HTMLElement
    const field = () => document.querySelector('[data-slot="list-search"]') as HTMLElement
    expect(tokens().className).not.toMatch(/(^|\s)hidden(\s|$)/)
    expect(field().className).toContain('sm:max-w-md')
    rerender(
      <ListToolbar
        search={props(true)}
        start={<button type="button">Status: Open</button>}
        end={<button type="button">Views</button>}
      />
    )
    // Out of the row (and out of the tab order), never dimmed in place.
    expect(tokens().className).toMatch(/(^|\s)hidden(\s|$)/)
    expect(tokens()).toHaveAttribute('inert')
    // No 28rem cap and no held width: the field grows into the room, up to
    // a long text field's width on a wide screen.
    expect(field().className).toContain('sm:max-w-(--field-max-multiline)')
    expect(field().className).not.toContain('sm:max-w-md')
    expect(field().style.width).toBe('')
    // The end group keeps its place at the row's end.
    const end = document.querySelector('[data-slot="list-toolbar-end"]') as HTMLElement
    expect(end.className).toContain('ms-auto')
  })

  it('on a phone never puts the tokens in a sideways strip: only the ones that filter show, wrapping', () => {
    render(
      <ListToolbar
        search={{ value: '', onChange: () => {}, placeholder: 'Search things' }}
        start={
          <>
            <button type="button">Kind: Appeared</button>
            <button type="button" aria-pressed="true">
              Internet-facing
            </button>
          </>
        }
        end={<button type="button">Views</button>}
        below={<span>chip</span>}
      />
    )
    const tokens = document.querySelector('[data-slot="list-toolbar-tokens"]') as HTMLElement
    // Owner report 2026-11-20: a strip that scrolls sideways reads as hidden buttons.
    expect(tokens.className).not.toContain('overflow-x-auto')
    expect(tokens.className).not.toContain('flex-nowrap')
    expect(tokens.className).toContain('@max-md/toolbar:flex-wrap')
    // Line 2, the whole line; the tokens that do not filter are in the sheet.
    expect(tokens.className).toContain('@max-md/toolbar:row-start-2')
    expect(tokens.className).toContain('@max-md/toolbar:col-end-4')
    expect(tokens.className).toContain(
      '@max-md/toolbar:[&>*:not([data-filtered=true],[aria-pressed=true]):not(:has([data-filtered=true],[aria-pressed=true]))]:hidden'
    )
    // Desktop: the wrapper draws no box, the row is as before.
    expect(tokens.className).toMatch(/(^|\s)contents(\s|$)/)
    // The chips row follows on line 2, or on line 3 under drawn tokens.
    const below = screen.getByTestId('data-table-toolbar-below')
    expect(below.className).toContain('@max-md/toolbar:row-start-2')
    expect(below.className).toContain(
      '@max-md/toolbar:group-has-[[data-slot=list-toolbar-tokens]:not([data-empty])]/toolbar:row-start-3'
    )
  })

  it('on a phone keeps every token drawn when the list has its own filter control (no sheet holds them)', () => {
    render(
      <ListToolbar
        search={{ value: '', onChange: () => {}, placeholder: 'Search entries' }}
        filter={<button type="button">Filters</button>}
        start={<button type="button">Show: Entries</button>}
      />
    )
    const tokens = document.querySelector('[data-slot="list-toolbar-tokens"]') as HTMLElement
    // Acceptance 2026-11-21 (/scope): the list switch was hidden on a phone
    // and no sheet held it, so Exclusions could not be reached.
    expect(tokens.className).toContain('@max-md/toolbar:row-start-2')
    expect(tokens.className).not.toContain(':hidden')
    expect(document.querySelector('[data-phone-filters]')).toBeNull()
  })

  it('on a phone gives a list without a facet panel one Filters button with the count, opening a sheet of the tokens', async () => {
    const user = userEvent.setup()
    render(
      <ListToolbar
        start={
          <>
            <div data-slot="filter-select" data-filtered="false">
              <button type="button">Kind: Appeared</button>
            </div>
            <div data-slot="filter-select" data-filtered="true">
              <button type="button">Status: Pending</button>
            </div>
            <button type="button" aria-pressed="true">
              Internet-facing
            </button>
          </>
        }
        end={<button type="button">Refresh</button>}
      />
    )
    const lead = document.querySelector('[data-slot="list-toolbar-lead"]') as HTMLElement
    // No search: the button starts the first line, the end group ends it.
    expect(lead.className).toContain('@max-md/toolbar:row-start-1')
    const button = lead.querySelector('[data-phone-filters]') as HTMLElement
    expect(button).toBeTruthy()
    // A phone only: from a 28rem toolbar the tokens are drawn in the row.
    expect(button.className).toContain('@md/toolbar:hidden')
    // Two tokens filter: the chosen status and the pressed toggle.
    expect(button).toHaveAccessibleName('Filters, 2 active')
    await user.click(button)
    const sheet = await screen.findByRole('dialog')
    expect(sheet.textContent).toContain('Kind: Appeared')
    expect(sheet.textContent).toContain('Status: Pending')
  })

  it('on a phone shows the tokens at the top of the facet sheet its Filters button opens', async () => {
    const user = userEvent.setup()
    function Page() {
      const [open, setOpen] = useState(false)
      return (
        <>
          <ListToolbar
            search={{ value: '', onChange: () => {}, placeholder: 'Search things' }}
            filterToggle={{
              open: false,
              onToggle: () => {},
              onOpenSheet: () => setOpen(true),
              activeCount: 0,
              controlsId: 'panel',
              sheetOnly: true,
            }}
            start={<button type="button">State: Open</button>}
          />
          <FilterSheet open={open} onOpenChange={setOpen} title="Finding filters">
            <p>facets</p>
          </FilterSheet>
        </>
      )
    }
    render(<Page />)
    // One filter entry: no second Filters button of the toolbar's own.
    expect(document.querySelector('[data-phone-filters]')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Filters' }))
    const sheet = await screen.findByRole('dialog')
    const host = sheet.querySelector('[data-slot="filter-sheet-tokens"]') as HTMLElement
    expect(host.textContent).toContain('State: Open')
  })

  it('has the same boxes with and without a chips row, so the first chip moves nothing', () => {
    const classes = () => {
      const q = (slot: string) =>
        (document.querySelector(`[data-slot="${slot}"]`) as HTMLElement).className
      return {
        region: q('list-toolbar-region'),
        layout: q('list-toolbar-layout'),
        toolbar: q('list-toolbar'),
        lead: q('list-toolbar-lead'),
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
    expect(container.querySelector('[data-slot="list-search"]')!.className).not.toMatch(/max-w-xl/)
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

describe('ListToolbar fold', () => {
  it('asks the search for less room once the toolbar folds, so a token stays on its line', () => {
    const { container } = render(<Search />)
    const field = container.querySelector('[data-slot="list-search"]') as HTMLElement
    expect(field.className).toContain('group-data-[fold=true]/toolbar:basis-48')
  })
})

describe('ListToolbar overflow', () => {
  it('moves the tokens behind the Filters button when the folded toolbar still wraps', () => {
    const origRO = globalThis.ResizeObserver
    const rect = HTMLElement.prototype.getBoundingClientRect
    const offset = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth')
    globalThis.ResizeObserver = class {
      constructor(private cb: () => void) {}
      observe() {
        this.cb()
      }
      unobserve() {}
      disconnect() {}
    } as unknown as typeof ResizeObserver
    Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
      configurable: true,
      get: () => 10,
    })
    // The status token always sits a row below the search: wrapped at any fold.
    HTMLElement.prototype.getBoundingClientRect = function () {
      const top = this.textContent === 'Status: Online' ? 40 : 0
      return {
        top,
        width: 700,
        height: 32,
        left: 0,
        right: 700,
        bottom: top + 32,
        x: 0,
        y: top,
      } as DOMRect
    }
    try {
      const { container } = render(<Search />)
      const region = container.querySelector('[data-slot="list-toolbar-region"]') as HTMLElement
      expect(region.dataset.overflow).toBe('true')
      const tokens = container.querySelector('[data-slot="list-toolbar-tokens"]') as HTMLElement
      expect(tokens.className).toContain('hidden')
      const trigger = container.querySelector('[data-phone-filters]') as HTMLElement
      expect(trigger.className).not.toContain('@md/toolbar:hidden')
    } finally {
      globalThis.ResizeObserver = origRO
      HTMLElement.prototype.getBoundingClientRect = rect
      if (offset) Object.defineProperty(HTMLElement.prototype, 'offsetWidth', offset)
    }
  })
})
