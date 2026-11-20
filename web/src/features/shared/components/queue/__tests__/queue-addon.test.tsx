/**
 * The queue add-on: the decision controls (two direct decisions and More,
 * the four-eyes rule, the permission gate), the decide-by date with its
 * overdue state, the reason dialog and the status region.
 */
import { describe, it, expect, vi } from 'vitest'
import { useState } from 'react'
import { act, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react'

vi.mock('@/components/ui/action-menu', () => ({
  ActionMenu: ({
    items,
    label,
    trigger,
  }: {
    items: { id: string; label: string }[]
    label: string
    trigger: React.ReactNode
  }) => (
    <div role="group" aria-label={label} data-items={items.map((i) => i.id).join(',')}>
      {trigger}
    </div>
  ),
}))

import {
  QueueCard,
  QueueDecideBy,
  QueueDecisionActions,
  QueueEmpty,
  QueueReasonDialog,
  decideByState,
  formatDecideByDate,
  useQueueAnnouncer,
} from '..'

const NOW = new Date('2026-11-17T12:00:00Z')

describe('decideByState', () => {
  it('is none without a usable date', () => {
    expect(decideByState(undefined, NOW)).toBe('none')
    expect(decideByState('', NOW)).toBe('none')
    expect(decideByState('not a date', NOW)).toBe('none')
  })
  it('is due before the moment and overdue after it', () => {
    expect(decideByState('2026-11-17T12:00:01Z', NOW)).toBe('due')
    expect(decideByState('2026-11-17T11:59:59Z', NOW)).toBe('overdue')
  })
})

describe('formatDecideByDate', () => {
  it('leaves the year out when it is this year', () => {
    expect(formatDecideByDate('2026-11-20T12:00:00Z', 'en', NOW)).not.toMatch(/2026/)
    expect(formatDecideByDate('2027-01-20T12:00:00Z', 'en', NOW)).toMatch(/2027/)
  })
})

describe('QueueDecideBy', () => {
  it('shows a date while there is time', () => {
    const { container } = render(<QueueDecideBy value="2026-11-20T12:00:00Z" now={NOW} />)
    const el = container.querySelector('[data-slot="queue-decide-by"]')
    expect(el).toHaveAttribute('data-state', 'due')
    expect(el?.textContent).not.toMatch(/Overdue/)
    expect(el).toHaveAttribute('datetime', '2026-11-20T12:00:00Z')
  })
  it('says Overdue with the date once the moment has passed', () => {
    const { container } = render(<QueueDecideBy value="2026-11-10T12:00:00Z" now={NOW} />)
    const el = container.querySelector('[data-slot="queue-decide-by"]')
    expect(el).toHaveAttribute('data-state', 'overdue')
    expect(el?.textContent).toMatch(/^Overdue, /)
  })
  it('is the empty cell when nothing waits', () => {
    const { container } = render(<QueueDecideBy value={undefined} />)
    expect(container.querySelector('[data-slot="queue-decide-by"]')).toBeNull()
    expect(container.querySelector('[data-slot="empty-cell"]')).toHaveTextContent('—')
  })
})

describe('QueueDecisionActions', () => {
  const base = { name: 'Request A', onApprove: vi.fn(), onReject: vi.fn() }

  it('offers two direct decisions, named after the item', () => {
    render(<QueueDecisionActions {...base} canDecide />)
    const buttons = screen.getAllByRole('button')
    expect(buttons).toHaveLength(2)
    fireEvent.click(screen.getByRole('button', { name: 'Approve Request A' }))
    fireEvent.click(screen.getByRole('button', { name: 'Reject Request A' }))
    expect(base.onApprove).toHaveBeenCalledTimes(1)
    expect(base.onReject).toHaveBeenCalledTimes(1)
  })

  // Each page's own labels: the accessible name is what the button says plus
  // the item, never a fixed "Approve" / "Reject".
  it.each([
    ['approvals', undefined, undefined, 'Approve Request A', 'Reject Request A'],
    ['duplicates', 'Merge', 'Keep separate', 'Merge Request A', 'Keep separate Request A'],
    ['suggestions', 'Accept', 'Dismiss', 'Accept Request A', 'Dismiss Request A'],
  ])('%s: the buttons are announced by their own label', (_page, a, r, approveName, rejectName) => {
    render(<QueueDecisionActions {...base} canDecide approveLabel={a} rejectLabel={r} />)
    expect(screen.getByRole('button', { name: approveName })).toHaveTextContent(a ?? 'Approve')
    expect(screen.getByRole('button', { name: rejectName })).toHaveTextContent(r ?? 'Reject')
    expect(screen.queryAllByRole('button', { name: /^(Approve|Reject) / })).toHaveLength(a ? 0 : 2)
  })

  it('takes a whole accessible name when label + item does not read well', () => {
    render(
      <QueueDecisionActions
        {...base}
        canDecide
        approveLabel="Merge"
        rejectLabel="Keep separate"
        rejectAccessibleName="Keep Request A separate"
      />
    )
    expect(screen.getByRole('button', { name: 'Merge Request A' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Keep Request A separate' })).toHaveTextContent(
      'Keep separate'
    )
  })

  it('says the sign-in step on the first decision only when it has one', () => {
    const { rerender } = render(<QueueDecisionActions {...base} canDecide />)
    expect(screen.getByRole('button', { name: 'Approve Request A' })).not.toHaveAttribute(
      'aria-describedby'
    )
    rerender(
      <QueueDecisionActions {...base} canDecide stepUpHint="You confirm your sign-in first." />
    )
    const approve = screen.getByRole('button', { name: 'Approve Request A' })
    expect(approve).toHaveAccessibleDescription('You confirm your sign-in first.')
    expect(approve).toHaveAttribute('data-variant', 'outline')
    expect(screen.getByRole('button', { name: 'Reject Request A' })).not.toHaveAttribute(
      'aria-describedby'
    )
  })

  it('renders nothing without the permission and without menu items', () => {
    const { container } = render(<QueueDecisionActions {...base} canDecide={false} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('four eyes: your own request has no decision control, and says why', () => {
    const { container } = render(<QueueDecisionActions {...base} canDecide own />)
    expect(screen.queryByRole('button')).toBeNull()
    const own = container.querySelector('[data-slot="queue-own-request"]')
    expect(own).toHaveTextContent('Your request')
    expect(own).toHaveTextContent('Someone else decides a request you made.')
    // Reachable by keyboard, so the reason can be read on focus.
    expect(own).toHaveAttribute('tabindex', '0')
  })

  it('four eyes on a card: the reason is written out', () => {
    const { container } = render(<QueueDecisionActions {...base} canDecide own layout="card" />)
    const own = container.querySelector('p[data-slot="queue-own-request"]')
    expect(own).toHaveTextContent('Your request Someone else decides a request you made.')
  })

  it('compact (a phone card): one main action, the second decision first in More', () => {
    const onReject = vi.fn()
    render(
      <QueueDecisionActions
        {...base}
        onReject={onReject}
        canDecide
        layout="compact"
        menu={[{ id: 'remind', label: 'Remind' }]}
      />
    )
    expect(screen.getByRole('button', { name: 'Approve Request A' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Reject Request A' })).toBeNull()
    expect(screen.getByRole('group', { name: 'Actions for Request A' })).toHaveAttribute(
      'data-items',
      'queue-reject,remind'
    )
  })

  it('compact: your own request reads as in a row, with no decision in More', () => {
    const { container } = render(
      <QueueDecisionActions
        {...base}
        canDecide
        own
        layout="compact"
        menu={[{ id: 'remind', label: 'Remind' }]}
      />
    )
    const own = container.querySelector('span[data-slot="queue-own-request"]')
    expect(own).toHaveTextContent('Your request')
    expect(own).toHaveAttribute('tabindex', '0')
    expect(screen.getByRole('group', { name: 'Actions for Request A' })).toHaveAttribute(
      'data-items',
      'remind'
    )
  })

  it('compact without the permission keeps only the menu the user may use', () => {
    const { container, rerender } = render(
      <QueueDecisionActions {...base} canDecide={false} layout="compact" />
    )
    expect(container).toBeEmptyDOMElement()
    rerender(
      <QueueDecisionActions
        {...base}
        canDecide={false}
        layout="compact"
        menu={[{ id: 'remind', label: 'Remind' }]}
      />
    )
    expect(screen.getByRole('group', { name: 'Actions for Request A' })).toHaveAttribute(
      'data-items',
      'remind'
    )
  })

  it('puts everything else under one More, named after the item', () => {
    render(
      <QueueDecisionActions
        {...base}
        canDecide
        menu={[
          { id: 'remind', label: 'Remind' },
          { id: 'cancel', label: 'Cancel', destructive: true },
        ]}
      />
    )
    const more = screen.getByRole('group', { name: 'Actions for Request A' })
    expect(more).toHaveAttribute('data-items', 'remind,cancel')
    expect(screen.getAllByRole('button')).toHaveLength(3)
  })

  it('is inert while the item is being saved', () => {
    render(<QueueDecisionActions {...base} canDecide busy menu={[{ id: 'x', label: 'X' }]} />)
    for (const b of screen.getAllByRole('button')) expect(b).toBeDisabled()
  })
})

describe('QueueReasonDialog', () => {
  function setup(over: Partial<React.ComponentProps<typeof QueueReasonDialog>> = {}) {
    const props = {
      open: true,
      onOpenChange: vi.fn(),
      title: 'Reject request',
      description: 'Give a reason.',
      reason: '',
      onReasonChange: vi.fn(),
      reasonLabel: 'Reason for rejection',
      confirmLabel: 'Reject',
      onConfirm: vi.fn(),
      ...over,
    }
    render(<QueueReasonDialog {...props} />)
    return props
  }

  it('keeps the decision inert until a reason is typed', () => {
    setup()
    expect(screen.getByRole('button', { name: 'Reject' })).toBeDisabled()
  })
  it('whitespace is not a reason', () => {
    setup({ reason: '   ' })
    expect(screen.getByRole('button', { name: 'Reject' })).toBeDisabled()
  })
  it('sends with a reason, and names the field', () => {
    const props = setup({ reason: 'Reachable' })
    expect(screen.getByRole('textbox', { name: 'Reason for rejection' })).toHaveValue('Reachable')
    fireEvent.click(screen.getByRole('button', { name: 'Reject' }))
    expect(props.onConfirm).toHaveBeenCalled()
    expect(screen.getByText('9/2000')).toBeInTheDocument()
  })
  it('says why a save failed and ties it to the field', () => {
    setup({ reason: 'Reachable', error: 'Failed to reject request' })
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('Failed to reject request')
    expect(screen.getByRole('textbox')).toHaveAttribute('aria-describedby', alert.id)
    expect(screen.getByRole('textbox')).toHaveAttribute('aria-invalid', 'true')
  })
  it('Cancel closes without deciding', () => {
    const props = setup({ reason: 'x' })
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(props.onOpenChange).toHaveBeenCalledWith(false)
    expect(props.onConfirm).not.toHaveBeenCalled()
  })
  it('gives the focus back to the control that opened it', async () => {
    function Harness() {
      const [open, setOpen] = useState(false)
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>
            Reject row
          </button>
          <QueueReasonDialog
            open={open}
            onOpenChange={setOpen}
            title="Reject request"
            description="Give a reason."
            reason=""
            onReasonChange={() => {}}
            reasonLabel="Reason for rejection"
            confirmLabel="Reject"
            onConfirm={() => {}}
          />
        </>
      )
    }
    render(<Harness />)
    const opener = screen.getByRole('button', { name: 'Reject row' })
    opener.focus()
    fireEvent.click(opener)
    const field = await screen.findByRole('textbox', { name: 'Reason for rejection' })
    fireEvent.keyDown(field, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(opener).toHaveFocus())
  })
  it('finds the same control of the same item when the list drew the row anew', async () => {
    function Harness() {
      const [open, setOpen] = useState(false)
      const [drawn, setDrawn] = useState(0)
      return (
        <>
          <div data-queue-item="r1">
            <button
              key={drawn}
              type="button"
              data-slot="queue-reject"
              onClick={() => {
                setOpen(true)
                setDrawn((n) => n + 1)
              }}
            >
              Reject row {drawn}
            </button>
          </div>
          <QueueReasonDialog
            open={open}
            onOpenChange={setOpen}
            title="Reject request"
            description="Give a reason."
            reason=""
            onReasonChange={() => {}}
            reasonLabel="Reason for rejection"
            confirmLabel="Reject"
            onConfirm={() => {}}
          />
        </>
      )
    }
    render(<Harness />)
    const first = screen.getByRole('button', { name: 'Reject row 0' })
    first.focus()
    fireEvent.click(first)
    const field = await screen.findByRole('textbox', { name: 'Reason for rejection' })
    fireEvent.keyDown(field, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(screen.getByRole('button', { name: 'Reject row 1' })).toHaveFocus())
  })
})

describe('useQueueAnnouncer', () => {
  it('holds the last outcome in one polite status region', () => {
    const { result } = renderHook(() => useQueueAnnouncer())
    const view = render(result.current.region)
    const region = view.container.querySelector('[data-slot="queue-announcer"]')
    expect(region).toHaveAttribute('role', 'status')
    expect(region).toHaveAttribute('aria-live', 'polite')
    expect(region).toBeEmptyDOMElement()
    act(() => result.current.announce('Approval request rejected'))
    view.rerender(result.current.region)
    expect(view.container).toHaveTextContent('Approval request rejected')
  })
  it('the same sentence twice in a row is a new text each time', () => {
    const { result } = renderHook(() => useQueueAnnouncer())
    act(() => result.current.announce('Done'))
    const first = render(result.current.region).container.textContent
    act(() => result.current.announce('Done'))
    const second = render(result.current.region).container.textContent
    expect(first).not.toBe(second)
  })
})

describe('QueueCard and QueueEmpty', () => {
  const slots = (root: HTMLElement) =>
    [...root.querySelectorAll('[data-slot^="queue-card-"]')].map((n) => n.getAttribute('data-slot'))

  it('draws the title line, the reason, then the facts line with the decision at its end', () => {
    const { container } = render(
      <QueueCard title="T" state="S" meta={['M1', null, 'M2']} reason="R" actions="A" />
    )
    expect(slots(container)).toEqual([
      'queue-card-head',
      'queue-card-title',
      'queue-card-state',
      'queue-card-reason',
      'queue-card-more',
      'queue-card-line',
      'queue-card-meta',
      'queue-card-actions',
    ])
    // Next to the decision only the first fact; the others wrap above it as
    // whole words (never a one-line, ellipsis-cut line); an empty item is left out.
    const meta = container.querySelector('[data-slot="queue-card-meta"]')
    expect(meta).toHaveTextContent('M1')
    expect(meta).not.toHaveTextContent('M2')
    expect(container.querySelector('[data-slot="queue-card-more"]')).toHaveTextContent('M2')
    expect(container.querySelector('[data-one-line]')).toBeNull()
  })

  it('keeps every fact on the one wrapping line when nothing sits at the end', () => {
    const { container } = render(<QueueCard title="T" meta={['M1', 'M2']} />)
    expect(container.querySelector('[data-slot="queue-card-more"]')).toBeNull()
    expect(container.querySelector('[data-slot="queue-card-meta"]')).toHaveTextContent('M1')
    expect(container.querySelector('[data-slot="queue-card-meta"]')).toHaveTextContent('M2')
  })

  it('leaves out the empty slots: a bare card is its title line only', () => {
    const { container } = render(<QueueCard title="T" />)
    expect(slots(container)).toEqual(['queue-card-head', 'queue-card-title'])
  })

  it('draws no link for a javascript: href', () => {
    const { container } = render(<QueueCard title="T" meta={['M']} href="javascript:alert(1)" />)
    expect(container.querySelector('[data-slot="queue-card-open"]')).toBeNull()
  })

  it('ends with a chevron to the item when there is no decision to draw', () => {
    const { container } = render(<QueueCard title="T" meta={['M']} href="/findings/1" />)
    expect(container.querySelector('a[href="/findings/1"]')).not.toBeNull()
    const open = container.querySelector('a[data-slot="queue-card-open"]')
    expect(open).toHaveAttribute('href', '/findings/1')
    // A pointer target only: the title is the link for the keyboard.
    expect(open).toHaveAttribute('tabindex', '-1')
    expect(open).toHaveAttribute('aria-hidden', 'true')
    expect(open).toHaveClass('inline-flex')
  })

  it('keeps the chevron for the case where the decision draws nothing', () => {
    const { container } = render(
      <QueueCard title="T" meta={['M']} href="/findings/1" actions={<span>Approve</span>} />
    )
    // Hidden while the actions slot holds something (CSS `peer-empty`).
    expect(container.querySelector('[data-slot="queue-card-actions"]')).toHaveClass('peer')
    expect(container.querySelector('[data-slot="queue-card-open"]')).toHaveClass(
      'hidden',
      'peer-empty:inline-flex'
    )
  })

  it("offers the row's checkbox in select mode", () => {
    const onSelectedChange = vi.fn()
    render(
      <QueueCard
        title="T"
        selectLabel="Select T"
        selection={{ selectable: true, selected: false, onSelectedChange }}
      />
    )
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select T' }))
    expect(onSelectedChange).toHaveBeenCalledWith(true)
  })

  it('names the kind of empty queue', () => {
    const { container } = render(<QueueEmpty kind="nothing-waiting" title="Nothing waits" />)
    expect(container.querySelector('[data-kind="nothing-waiting"]')).toHaveTextContent(
      'Nothing waits'
    )
  })
})
