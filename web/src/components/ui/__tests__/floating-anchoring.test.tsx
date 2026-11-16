/**
 * Smart anchoring of the kit's floating surfaces (web/docs/ui-style-contract.md,
 * "Floating surfaces"): a popup lines up with its trigger's start edge
 * unless it would then cross the room it has (the screen less its gutter, or
 * the drawer it was opened from), its width is its content's, the padding grows for the safe area and a fixed bottom row,
 * a select list never covers its trigger, a heading over one item hides, and
 * shortcut hints are not shown under a coarse pointer.
 */
import { describe, it, expect, afterAll, afterEach, beforeAll } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import * as React from 'react'

import {
  chooseAlign,
  floatingBounds,
  floatingPadding,
  FLOATING_MENU_MAX_WIDTH,
  FLOATING_MENU_MIN_WIDTH,
  FLOATING_MENU_MIN_WIDTH_ICONS,
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
  // A 390 px phone less its 16 px gutters.
  const phone = { left: 16, right: 374 }
  it('lines a popup up with the start edge of its trigger when it fits that way', () => {
    expect(chooseAlign({ left: 16, right: 52 }, 160, phone)).toBe('start')
    // In the right half of the screen too: the old half-screen rule said end.
    expect(chooseAlign({ left: 200, right: 240 }, 160, phone)).toBe('start')
  })
  it('lines it up with the end edge only when the start would cross the room', () => {
    expect(chooseAlign({ left: 338, right: 374 }, 160, phone)).toBe('end')
    expect(chooseAlign({ left: 220, right: 260 }, 160, phone)).toBe('end')
  })
  it('keeps the start edge at the exact fit (rounding allowed)', () => {
    expect(chooseAlign({ left: 214, right: 250 }, 160, phone)).toBe('start')
    expect(chooseAlign({ left: 214.4, right: 250 }, 160, phone)).toBe('start')
  })
  it('takes the edge with more room when neither fits', () => {
    expect(chooseAlign({ left: 40, right: 76 }, 358, phone)).toBe('start')
    expect(chooseAlign({ left: 300, right: 336 }, 358, phone)).toBe('end')
  })
  it('mirrors on a right-to-left page (start is the right edge)', () => {
    expect(chooseAlign({ left: 338, right: 374 }, 160, phone, 'rtl')).toBe('start')
    expect(chooseAlign({ left: 150, right: 190 }, 160, phone, 'rtl')).toBe('start')
    expect(chooseAlign({ left: 16, right: 52 }, 160, phone, 'rtl')).toBe('end')
  })
  it('keeps a menu from a right-hand drawer under its trigger', () => {
    // 1440 px screen, 560 px drawer at the right, status button at its left.
    const drawer = floatingBounds(1440, { left: 16, right: 16 }, 160, { left: 880, right: 1440 })
    expect(chooseAlign({ left: 904, right: 980 }, 160, drawer)).toBe('start')
    // The drawer's own More at its right edge.
    expect(chooseAlign({ left: 1392, right: 1424 }, 160, drawer)).toBe('end')
  })
})

describe('floatingBounds', () => {
  const pad = { left: 16, right: 16 }
  it('is the screen less its gutters outside an overlay', () => {
    expect(floatingBounds(390, pad, 160, null)).toEqual({ left: 16, right: 374, overlay: false })
  })
  it('is the overlay less its inset when the popup fits in it', () => {
    expect(floatingBounds(1440, pad, 256, { left: 880, right: 1440 })).toEqual({
      left: 888,
      right: 1424,
      overlay: true,
    })
  })
  it('never reaches past the screen gutter (an overlay as wide as the screen)', () => {
    expect(floatingBounds(390, pad, 160, { left: 0, right: 390 })).toEqual({
      left: 16,
      right: 374,
      overlay: true,
    })
  })
  it('falls back to the screen when the popup is wider than the overlay', () => {
    expect(floatingBounds(1024, pad, 400, { left: 700, right: 1024 })).toEqual({
      left: 16,
      right: 1008,
      overlay: false,
    })
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

// jsdom has no layout: give the open menu a width (Radix positions it later).
const realRect = HTMLElement.prototype.getBoundingClientRect
let menuWidth = 160
beforeAll(() => {
  HTMLElement.prototype.getBoundingClientRect = function (this: HTMLElement) {
    if (this.dataset.slot === 'dropdown-menu-content') return rect(0, 0, menuWidth, 80)
    return realRect.call(this)
  }
})
afterAll(() => {
  HTMLElement.prototype.getBoundingClientRect = realRect
})

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
    menuWidth = 160
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
      expect(align).toBe(triggerLeft + 160 <= 374 ? 'start' : 'end')
    })
    unmount()
    return align
  }

  it('opens a menu whose trigger is at the left aligned to its start edge', async () => {
    expect(await openedAlign(16)).toBe('start')
  })

  it('opens a menu right of the middle aligned to its start edge when it fits', async () => {
    expect(await openedAlign(200)).toBe('start')
  })

  it('opens a menu whose trigger is at the right edge aligned to its end edge', async () => {
    expect(await openedAlign(338)).toBe('end')
  })

  it('keeps a menu opened in a right-hand drawer under its trigger, inside the drawer', async () => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1440 })
    function InDrawer() {
      const drawerRef = React.useCallback((el: HTMLDivElement | null) => {
        if (el) el.getBoundingClientRect = () => rect(880, 0, 560, 900)
      }, [])
      const ref = React.useCallback((el: HTMLButtonElement | null) => {
        if (el) el.getBoundingClientRect = () => rect(1300, 100, 76, 32)
      }, [])
      return (
        <div role="dialog" aria-label="Finding" ref={drawerRef}>
          <DropdownMenu>
            <DropdownMenuTrigger ref={ref}>New</DropdownMenuTrigger>
            <DropdownMenuContent avoidCollisions={false}>
              <DropdownMenuItem>Confirmed</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      )
    }
    render(<InDrawer />)
    await userEvent.click(screen.getByRole('button', { name: 'New' }))
    const menu = await screen.findByRole('menu')
    // 1300 + 160 crosses the screen gutter at 1424: end-aligned, as it fits
    // leftwards inside the drawer, whose inner edge (880 + 8) becomes the
    // left collision padding.
    await waitFor(() => expect(menu.getAttribute('data-align')).toBe('end'))
    expect(menu.style.getPropertyValue('--float-gutter-x')).toBe(`${888 + 16}px`)
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

  it('still passes the trigger and the content to caller refs', async () => {
    const objectRef = React.createRef<HTMLButtonElement>()
    const contentRef = React.createRef<HTMLDivElement>()
    let fromCallback: HTMLButtonElement | null = null
    render(
      <>
        <DropdownMenu>
          <DropdownMenuTrigger ref={objectRef}>A</DropdownMenuTrigger>
          <DropdownMenuContent ref={contentRef}>
            <DropdownMenuItem>One</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <DropdownMenu>
          <DropdownMenuTrigger ref={(el) => void (fromCallback = el)}>B</DropdownMenuTrigger>
        </DropdownMenu>
      </>
    )
    expect(objectRef.current?.textContent).toBe('A')
    expect((fromCallback as HTMLButtonElement | null)?.textContent).toBe('B')
    await userEvent.click(screen.getByRole('button', { name: 'A' }))
    expect(await screen.findByRole('menu')).toBe(contentRef.current)
  })
})

describe('menu width', () => {
  it('is the content width between the floor and 360 px, with no fixed width', async () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem>Confirmed</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    )
    await userEvent.click(screen.getByRole('button', { name: 'Open' }))
    const cls = (await screen.findByRole('menu')).className
    expect(cls).toContain('max-w-[min(22.5rem,calc(100vw_-_var(--float-gutter-x,2rem)))]')
    expect(cls).toContain('min-w-[max(8rem,var(--radix-dropdown-menu-trigger-width,0px))]')
    expect(cls).toContain(
      'has-[svg]:min-w-[max(10rem,var(--radix-dropdown-menu-trigger-width,0px))]'
    )
    expect([
      FLOATING_MENU_MIN_WIDTH,
      FLOATING_MENU_MIN_WIDTH_ICONS,
      FLOATING_MENU_MAX_WIDTH,
    ]).toEqual([8, 10, 22.5].map((rem) => rem * 16))
    expect(cls).not.toMatch(/(^|\s)w-/)
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
