/**
 * Smart anchoring of the kit's floating surfaces (web/docs/ui-style-contract.md,
 * "Floating surfaces"): the alignment follows the half of the screen the
 * trigger is in, the padding grows for the safe area and a fixed bottom row,
 * a select list never covers its trigger, a heading over one item hides, and
 * shortcut hints are not shown under a coarse pointer.
 */
import { describe, it, expect, afterEach, beforeAll } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import * as React from 'react'

import {
  chooseAlign,
  floatingPadding,
  measureBottomObstruction,
  NO_FLOATING_ENVIRONMENT,
  useFloatingObstruction,
} from '../floating'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from '../dropdown-menu'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../select'

describe('chooseAlign', () => {
  const vw = 390
  it('lines a popup up with the start edge of a trigger in the start half', () => {
    expect(chooseAlign({ left: 16, right: 52 }, vw)).toBe('start')
    expect(chooseAlign({ left: 150, right: 190 }, vw)).toBe('start')
  })
  it('lines it up with the end edge of a trigger in the end half', () => {
    expect(chooseAlign({ left: 338, right: 374 }, vw)).toBe('end')
    expect(chooseAlign({ left: 200, right: 240 }, vw)).toBe('end')
  })
  it('treats a trigger centred on the screen as the end half', () => {
    expect(chooseAlign({ left: 175, right: 215 }, vw)).toBe('end')
  })
  it('mirrors on a right-to-left page (start is the right edge)', () => {
    expect(chooseAlign({ left: 338, right: 374 }, vw, 'rtl')).toBe('start')
    expect(chooseAlign({ left: 16, right: 52 }, vw, 'rtl')).toBe('end')
  })
})

describe('floatingPadding', () => {
  it('is the gutter on every side by default', () => {
    expect(floatingPadding(16, NO_FLOATING_ENVIRONMENT)).toEqual({
      top: 16,
      right: 16,
      bottom: 16,
      left: 16,
    })
  })
  it('is at least the safe area (notch, home indicator)', () => {
    const env = { safe: { top: 47, right: 0, bottom: 34, left: 59 }, bottomObstruction: 0 }
    expect(floatingPadding(16, env)).toEqual({ top: 47, right: 16, bottom: 34, left: 59 })
  })
  it('keeps the gutter above a fixed bottom row', () => {
    const env = { safe: { top: 0, right: 0, bottom: 34, left: 0 }, bottomObstruction: 72 }
    expect(floatingPadding(16, env).bottom).toBe(88)
  })
})

function rect(left: number, top: number, width: number, height: number): DOMRect {
  return {
    left,
    top,
    width,
    height,
    right: left + width,
    bottom: top + height,
    x: left,
    y: top,
    toJSON: () => ({}),
  } as DOMRect
}

function Menu({ triggerLeft }: { triggerLeft: number }) {
  const ref = React.useCallback(
    (el: HTMLButtonElement | null) => {
      if (el) el.getBoundingClientRect = () => rect(triggerLeft, 100, 36, 36)
    },
    [triggerLeft]
  )
  return (
    <DropdownMenu>
      <DropdownMenuTrigger ref={ref}>More</DropdownMenuTrigger>
      {/* jsdom has no viewport size: collision flips would decide instead. */}
      <DropdownMenuContent avoidCollisions={false}>
        <DropdownMenuItem>Rename</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

describe('auto alignment', () => {
  afterEach(() => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1024 })
  })

  async function openedAlign(triggerLeft: number) {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    const { unmount } = render(<Menu triggerLeft={triggerLeft} />)
    await userEvent.click(screen.getByRole('button', { name: 'More' }))
    const menu = await screen.findByRole('menu')
    // The placement settles after the positioning pass.
    let align: string | null = null
    await waitFor(() => {
      align = menu.getAttribute('data-align')
      expect(align).toBe(triggerLeft < 195 ? 'start' : 'end')
    })
    unmount()
    return align
  }

  it('opens a menu whose trigger is at the left aligned to its start edge', async () => {
    expect(await openedAlign(16)).toBe('start')
  })

  it('opens a menu whose trigger is at the right aligned to its end edge', async () => {
    expect(await openedAlign(338)).toBe('end')
  })

  it('keeps an alignment the call site sets', async () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Fixed</DropdownMenuTrigger>
        <DropdownMenuContent align="center">
          <DropdownMenuItem>One</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    )
    await userEvent.click(screen.getByRole('button', { name: 'Fixed' }))
    expect((await screen.findByRole('menu')).getAttribute('data-align')).toBe('center')
  })

  it('works with a controlled menu that a caller opens itself', async () => {
    function Controlled() {
      const [open, setOpen] = React.useState(false)
      const ref = React.useCallback((el: HTMLButtonElement | null) => {
        if (el) el.getBoundingClientRect = () => rect(338, 100, 36, 36)
      }, [])
      return (
        <>
          <button onClick={() => setOpen(true)}>Open from elsewhere</button>
          <DropdownMenu open={open} onOpenChange={setOpen}>
            <DropdownMenuTrigger ref={ref}>Row</DropdownMenuTrigger>
            <DropdownMenuContent avoidCollisions={false}>
              <DropdownMenuItem>One</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </>
      )
    }
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    render(<Controlled />)
    await userEvent.click(screen.getByRole('button', { name: 'Open from elsewhere' }))
    const menu = await screen.findByRole('menu')
    await waitFor(() => expect(menu.getAttribute('data-align')).toBe('end'))
  })

  it('still passes the trigger to a caller ref (object and callback refs)', () => {
    const objectRef = React.createRef<HTMLButtonElement>()
    let fromCallback: HTMLButtonElement | null = null
    render(
      <>
        <DropdownMenu>
          <DropdownMenuTrigger ref={objectRef}>A</DropdownMenuTrigger>
        </DropdownMenu>
        <DropdownMenu>
          <DropdownMenuTrigger ref={(el) => void (fromCallback = el)}>B</DropdownMenuTrigger>
        </DropdownMenu>
      </>
    )
    expect(objectRef.current?.textContent).toBe('A')
    expect((fromCallback as HTMLButtonElement | null)?.textContent).toBe('B')
  })
})

describe('select list', () => {
  beforeAll(() => {
    // jsdom has no layout: Radix Select scrolls the chosen option into view.
    Element.prototype.scrollIntoView ??= () => {}
  })
  it('opens below its trigger instead of over it (popper by default)', async () => {
    render(
      <Select>
        <SelectTrigger aria-label="Severity">
          <SelectValue placeholder="Pick" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="high">High</SelectItem>
          <SelectItem value="low">Low</SelectItem>
        </SelectContent>
      </Select>
    )
    await userEvent.click(screen.getByRole('combobox', { name: 'Severity' }))
    const list = await screen.findByRole('listbox')
    // Radix marks the popper wrapper; item-aligned has none.
    expect(list.closest('[data-radix-popper-content-wrapper]')).not.toBeNull()
  })
})

describe('fixed bottom row', () => {
  it('counts while shown and stops counting when hidden', () => {
    Object.defineProperty(window, 'innerHeight', { configurable: true, value: 844 })
    function Bar({ shown }: { shown: boolean }) {
      const ref = React.useRef<HTMLDivElement>(null)
      useFloatingObstruction(ref, shown)
      return (
        <div
          ref={(el) => {
            ref.current = el
            if (el) el.getBoundingClientRect = () => rect(0, 844 - 72, 390, 72)
          }}
        />
      )
    }
    const { rerender, unmount } = render(<Bar shown />)
    expect(measureBottomObstruction()).toBe(72)
    act(() => rerender(<Bar shown={false} />))
    expect(measureBottomObstruction()).toBe(0)
    unmount()
  })
})

describe('menu group label', () => {
  async function open(content: React.ReactNode) {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>{content}</DropdownMenuContent>
      </DropdownMenu>
    )
    await userEvent.click(screen.getByRole('button', { name: 'Open' }))
    await screen.findByRole('menu')
  }

  it('hides a heading over a single item (the item says it)', async () => {
    await open(
      <>
        <DropdownMenuLabel>Create</DropdownMenuLabel>
        <DropdownMenuItem>Import results</DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem>Approvals</DropdownMenuItem>
      </>
    )
    expect(screen.getByText('Create')).not.toBeVisible()
  })

  it('shows a heading over two items or more', async () => {
    await open(
      <DropdownMenuGroup>
        <DropdownMenuLabel>Export</DropdownMenuLabel>
        <DropdownMenuItem>CSV</DropdownMenuItem>
        <DropdownMenuItem>JSON</DropdownMenuItem>
      </DropdownMenuGroup>
    )
    expect(screen.getByText('Export')).toBeVisible()
  })

  it('keeps a label over no items (an account header)', async () => {
    await open(
      <>
        <DropdownMenuLabel>someone@example.com</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem>Sign out</DropdownMenuItem>
      </>
    )
    expect(screen.getByText('someone@example.com')).toBeVisible()
  })
})

describe('shortcut hints', () => {
  it('are hidden under a coarse pointer', async () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem>
            Search <DropdownMenuShortcut>/</DropdownMenuShortcut>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    )
    await userEvent.click(screen.getByRole('button', { name: 'Open' }))
    expect(await screen.findByText('/')).toHaveClass('pointer-coarse:hidden')
  })
})
