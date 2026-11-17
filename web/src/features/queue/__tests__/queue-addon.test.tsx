/**
 * The queue add-on: the decision controls (two direct decisions and More,
 * the four-eyes rule, the permission gate), the decide-by date with its
 * overdue state, the reason dialog and the status region.
 */
import { describe, it, expect, vi } from 'vitest'
import { act, fireEvent, render, renderHook, screen } from '@testing-library/react'

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
  it('is a dash when nothing waits', () => {
    const { container } = render(<QueueDecideBy value={undefined} />)
    expect(container.querySelector('[data-slot="queue-decide-by"]')).toBeNull()
    expect(container).toHaveTextContent('-')
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
  it('draws its slots in one order and leaves out the empty ones', () => {
    const { container } = render(<QueueCard title="T" marks="M" meta="W" reason="R" actions="A" />)
    const slots = [...container.querySelectorAll('[data-slot^="queue-card-"]')].map((n) =>
      n.getAttribute('data-slot')
    )
    expect(slots).toEqual([
      'queue-card-title',
      'queue-card-marks',
      'queue-card-meta',
      'queue-card-reason',
      'queue-card-actions',
    ])
    const bare = render(<QueueCard title="T" />).container
    expect(bare.querySelectorAll('[data-slot^="queue-card-"]')).toHaveLength(1)
  })
  it('names the kind of empty queue', () => {
    const { container } = render(<QueueEmpty kind="nothing-waiting" title="Nothing waits" />)
    expect(container.querySelector('[data-kind="nothing-waiting"]')).toHaveTextContent(
      'Nothing waits'
    )
  })
})
