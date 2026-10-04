import * as React from 'react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, render, renderHook, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { KeyRound, Trash2 } from 'lucide-react'

import {
  DetailHeader,
  DetailSheet,
  DetailTabs,
  useDetailTab,
  type DetailMenuItem,
} from '../detail-sheet-layout'

function renderSheet(props: Partial<React.ComponentProps<typeof DetailHeader>> = {}) {
  const onClose = vi.fn()
  render(
    <DetailSheet
      open
      onOpenChange={() => {}}
      header={<DetailHeader title="dmz-scanner-01" onClose={onClose} {...props} />}
      tabs={
        <DetailTabs
          tabs={[
            { value: 'overview', label: 'Overview' },
            { value: 'jobs', label: 'Jobs' },
          ]}
          value="overview"
          onValueChange={() => {}}
        />
      }
      panel="overview"
    >
      <p>Body</p>
    </DetailSheet>
  )
  return { onClose }
}

describe('DetailSheet + DetailHeader', () => {
  it('is a dialog named by the title, with the body as the tab panel', () => {
    renderSheet()
    expect(screen.getByRole('dialog', { name: 'dmz-scanner-01' })).toBeInTheDocument()
    expect(screen.getByRole('tabpanel', { name: 'overview' })).toHaveTextContent('Body')
  })

  it('wraps a long title instead of cutting it', () => {
    const long = 'a-very-long-sensor-name-that-is-the-only-identifier-on-screen-'.repeat(3)
    renderSheet({ title: long })
    const title = screen.getByRole('heading', { name: long })
    expect(title.className).toContain('break-words')
    expect(title.className).not.toContain('truncate')
  })

  it('joins the meta parts with a middle dot and skips empty ones', () => {
    renderSheet({ meta: ['Scanner · long-running', null, '', '10.0.0.5'] })
    expect(screen.getByText('Scanner · long-running · 10.0.0.5')).toBeInTheDocument()
  })

  it('renders the action row', () => {
    renderSheet({ actions: <button>Edit</button> })
    expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument()
  })

  it('closes from the close button', async () => {
    const { onClose } = renderSheet()
    // The Sheet's built-in close button is hidden by CSS; ours is in the header.
    const header = document.querySelector('[data-slot="detail-header"]') as HTMLElement
    await userEvent.click(within(header).getByRole('button', { name: 'Close' }))
    expect(onClose).toHaveBeenCalled()
  })

  it('has no ⋯ menu without items', () => {
    renderSheet({ menu: [] })
    expect(screen.queryByRole('button', { name: 'More actions' })).not.toBeInTheDocument()
  })

  it('lists menu items, destructive ones in the destructive colour after a divider', async () => {
    const rotate = vi.fn()
    const menu: DetailMenuItem[] = [
      { label: 'Rotate key', icon: KeyRound, onSelect: rotate },
      {
        label: 'Delete',
        icon: Trash2,
        destructive: true,
        separatorBefore: true,
        onSelect: vi.fn(),
      },
    ]
    renderSheet({ menu })
    await userEvent.click(screen.getByRole('button', { name: 'More actions' }))
    expect(await screen.findByRole('menuitem', { name: 'Delete' })).toHaveClass('text-destructive')
    expect(screen.getByRole('separator')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('menuitem', { name: 'Rotate key' }))
    expect(rotate).toHaveBeenCalled()
  })
})

describe('DetailTabs', () => {
  it('changes tab with the arrow keys', async () => {
    const onChange = vi.fn()
    render(
      <DetailTabs
        tabs={[
          { value: 'overview', label: 'Overview' },
          { value: 'jobs', label: 'Jobs' },
        ]}
        value="overview"
        onValueChange={onChange}
      />
    )
    screen.getByRole('tab', { name: 'Overview' }).focus()
    await userEvent.keyboard('{ArrowRight}')
    expect(onChange).toHaveBeenCalledWith('jobs')
  })
})

describe('useDetailTab', () => {
  beforeEach(() => window.history.replaceState(null, '', '/sensors'))

  it('starts on the first tab and writes others to the URL', () => {
    const { result } = renderHook(() => useDetailTab('view', ['overview', 'jobs'] as const))
    expect(result.current[0]).toBe('overview')
    act(() => result.current[1]('jobs'))
    expect(new URLSearchParams(window.location.search).get('view')).toBe('jobs')
  })

  it('ignores a value that names no tab', () => {
    window.history.replaceState(null, '', '/sensors?view=bogus')
    const { result } = renderHook(() => useDetailTab('view', ['overview', 'jobs'] as const))
    expect(result.current[0]).toBe('overview')
  })

  // Radix <Tabs> is controlled; re-selecting the active tab would rewrite the URL
  // and a subscriber would reflect it back onto `value` — a feedback loop. The
  // setter must be a no-op when the value is already active.
  it('does not write the URL when the active tab is set again', () => {
    window.history.replaceState(null, '', '/sensors?view=jobs')
    let dispatches = 0
    const bump = () => (dispatches += 1)
    window.addEventListener('openctem:url-params-changed', bump)
    const { result } = renderHook(() => useDetailTab('view', ['overview', 'jobs'] as const))
    act(() => result.current[1]('jobs'))
    window.removeEventListener('openctem:url-params-changed', bump)
    expect(dispatches).toBe(0)
    expect(new URLSearchParams(window.location.search).get('view')).toBe('jobs')
  })
})

describe('DetailSheet on phones', () => {
  const desktopWidth = window.innerWidth
  beforeEach(() => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
  })
  afterEach(() => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: desktopWidth })
  })

  function PhoneSheet({
    panel,
    phoneHeight,
    bodyRef,
  }: {
    panel?: string
    phoneHeight?: 'auto' | 'full'
    bodyRef?: React.Ref<HTMLDivElement>
  }) {
    return (
      <DetailSheet
        open
        onOpenChange={() => {}}
        header={<DetailHeader title="dmz-scanner-01" onClose={() => {}} />}
        panel={panel}
        phoneHeight={phoneHeight}
        bodyRef={bodyRef}
      >
        <p>Body of {panel}</p>
      </DetailSheet>
    )
  }

  const sheet = () => document.querySelector('[data-slot="detail-sheet"]') as HTMLElement
  const body = () => document.querySelector('[data-slot="detail-sheet-body"]') as HTMLElement

  it('is a bottom sheet of one fixed height by default', () => {
    render(<PhoneSheet panel="overview" />)
    expect(sheet()).toHaveClass('h-[92svh]', 'rounded-t-2xl')
    expect(sheet()).not.toHaveClass('max-h-[92svh]')
    // Clear of the iPhone home indicator.
    expect(sheet()).toHaveClass('pb-[env(safe-area-inset-bottom)]')
  })

  it('grows with its content only when asked to', () => {
    render(<PhoneSheet phoneHeight="auto" />)
    expect(sheet()).toHaveClass('max-h-[92svh]')
    expect(sheet()).not.toHaveClass('h-[92svh]')
  })

  it('starts a new tab at the top of the body', () => {
    const { rerender } = render(<PhoneSheet panel="overview" />)
    body().scrollTop = 480
    rerender(<PhoneSheet panel="overview" />)
    expect(body().scrollTop).toBe(480)
    rerender(<PhoneSheet panel="jobs" />)
    expect(body().scrollTop).toBe(0)
  })

  it('is a swipeable drawer with a grabber, still a dialog named by its title', () => {
    render(<PhoneSheet panel="overview" />)
    expect(sheet()).toHaveAttribute('data-vaul-drawer-direction', 'bottom')
    expect(screen.getByRole('dialog', { name: 'dmz-scanner-01' })).toBe(sheet())
    // The grabber is decorative; the Close button is the accessible way out.
    const handle = sheet().querySelector('[data-vaul-handle]') as HTMLElement
    expect(handle).toHaveAttribute('aria-hidden', 'true')
    expect(handle.querySelector('[data-vaul-handle-hitarea]')).not.toBeNull()
  })

  it('focuses the sheet itself on open, so no keyboard slides up', () => {
    render(<PhoneSheet panel="overview" />)
    expect(document.activeElement).toBe(sheet())
  })

  it('closes with Esc and from the 44px Close button', async () => {
    const onOpenChange = vi.fn()
    const onClose = vi.fn()
    render(
      <DetailSheet
        open
        onOpenChange={onOpenChange}
        header={<DetailHeader title="x" onClose={onClose} />}
      />
    )
    const close = screen.getByRole('button', { name: 'Close' })
    // 32px button, 44x44 hit area from ::after.
    expect(close).toHaveClass('size-8', 'after:absolute', 'after:-inset-1.5')
    await userEvent.click(close)
    expect(onClose).toHaveBeenCalled()
    await userEvent.keyboard('{Escape}')
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('returns focus to the control that opened it', async () => {
    function Opener() {
      const [open, setOpen] = React.useState(false)
      return (
        <>
          <button onClick={() => setOpen(true)}>Open details</button>
          <DetailSheet
            open={open}
            onOpenChange={setOpen}
            header={<DetailHeader title="x" onClose={() => setOpen(false)} />}
          />
        </>
      )
    }
    render(<Opener />)
    const button = screen.getByRole('button', { name: 'Open details' })
    await userEvent.click(button)
    expect(document.activeElement).toBe(sheet())
    await userEvent.keyboard('{Escape}')
    await vi.waitFor(() => expect(document.activeElement).toBe(button))
  })

  it('never drags from a field or the footer', () => {
    render(
      <DetailSheet
        open
        onOpenChange={() => {}}
        header={<DetailHeader title="x" onClose={() => {}} />}
        footer={<button>Send</button>}
      >
        <input aria-label="Search" />
        <textarea aria-label="Note" />
        <p>Plain text</p>
      </DetailSheet>
    )
    const search = screen.getByRole('textbox', { name: 'Search' })
    const note = screen.getByRole('textbox', { name: 'Note' })
    const text = screen.getByText('Plain text')
    for (const el of [search, note, text]) {
      el.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true }))
    }
    expect(search).toHaveAttribute('data-vaul-no-drag')
    expect(note).toHaveAttribute('data-vaul-no-drag')
    // Plain content drags the sheet (when the body is at its top).
    expect(text.closest('[data-vaul-no-drag]')).toBeNull()
    expect(
      screen.getByRole('button', { name: 'Send' }).closest('[data-vaul-no-drag]')
    ).not.toBeNull()
  })

  it('still hands the body to a caller that manages its scroll', () => {
    const ref = React.createRef<HTMLDivElement>()
    const { unmount } = render(<PhoneSheet panel="overview" bodyRef={ref} />)
    expect(ref.current).toBe(body())
    unmount()
    const fn = vi.fn()
    render(<PhoneSheet bodyRef={fn} />)
    expect(fn).toHaveBeenCalledWith(body())
  })
})

describe('DetailSheet on larger screens', () => {
  it('is the full-height side drawer, untouched by the phone height', () => {
    render(
      <DetailSheet
        open
        onOpenChange={() => {}}
        header={<DetailHeader title="x" onClose={() => {}} />}
      />
    )
    const el = document.querySelector('[data-slot="detail-sheet"]') as HTMLElement
    expect(el).toHaveClass('h-full', 'sm:max-w-xl')
    expect(el).not.toHaveAttribute('data-vaul-drawer')
    expect(el).not.toHaveClass('h-[92svh]')
    expect(el).not.toHaveClass('max-h-[92svh]')
  })
})
