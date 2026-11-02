/**
 * Queue page head: back link, reason heading that opens a menu to switch
 * reason (with counts, keyboard operable), count, why line, inventory link.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const state = vi.hoisted(() => ({
  hidden: [] as string[],
  push: vi.fn(),
  counts: {} as Record<string, number | undefined>,
}))

vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
  useLinkStatus: () => ({ pending: false }),
}))
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: state.push }) }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useVisibleSectionTabs: (rows: { module: string }[]) =>
    rows.filter((r) => !state.hidden.includes(r.module)),
}))
vi.mock('../use-attention-count', () => ({
  useAttentionCount: (id: string) => state.counts[id],
}))

import { AttentionQueueHeader } from '../attention-queue-header'

beforeEach(() => {
  state.hidden = []
  state.push.mockClear()
  state.counts = {
    validate_primary: 2,
    decide_monitoring: 7,
    no_owner: 549,
    context: 4,
    unscanned: 0,
    relationships: 12,
    duplicates: 3,
  }
})

describe('AttentionQueueHeader', () => {
  it('shows the back link, the reason as heading, its count, the why and the inventory link', () => {
    render(
      <AttentionQueueHeader reason="no_owner" count={549} inventoryHref="/assets?has_owner=false" />
    )
    expect(screen.getByRole('link', { name: 'Needs attention' })).toHaveAttribute(
      'href',
      '/assets/attention'
    )
    expect(screen.getByRole('heading', { level: 2, name: 'No owner' })).toBeInTheDocument()
    expect(screen.getByTestId('attention-queue-count')).toHaveTextContent('549 assets')
    expect(
      screen.getByText('Findings on these assets have nobody to assign to.')
    ).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /open in the inventory/i })).toHaveAttribute(
      'href',
      '/assets?has_owner=false'
    )
  })

  it('has no inventory link for a reason with no inventory view', () => {
    render(<AttentionQueueHeader reason="duplicates" count={3} />)
    expect(screen.queryByRole('link', { name: /open in the inventory/i })).toBeNull()
    expect(screen.getByTestId('attention-queue-count')).toHaveTextContent('3 pairs')
  })

  it('opens a menu of every reason with counts, the current one checked', async () => {
    const user = userEvent.setup()
    render(<AttentionQueueHeader reason="context" count={4} />)
    await user.click(screen.getByRole('button', { name: 'Criticality not set' }))
    const items = await screen.findAllByRole('menuitemradio')
    expect(items.map((i) => i.textContent)).toEqual([
      'Validate primary assets2',
      'Decide monitoring7',
      'No owner549',
      'Criticality not set4',
      'Not scanned in 30 days0',
      'Relationships12',
      'Possible duplicates3',
    ])
    expect(items[3]).toHaveAttribute('aria-checked', 'true')
    expect(items[2]).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByRole('menuitem', { name: 'All reasons' })).toBeInTheDocument()
  })

  it('switches reason with the keyboard and closes on Escape', async () => {
    const user = userEvent.setup()
    render(<AttentionQueueHeader reason="no_owner" count={549} />)
    const trigger = screen.getByRole('button', { name: 'No owner' })
    trigger.focus()
    await user.keyboard('{Enter}')
    await screen.findByRole('menu')
    await user.keyboard('{ArrowDown}{Enter}')
    expect(state.push).toHaveBeenCalledTimes(1)
    expect(state.push.mock.calls[0][0]).toMatch(/^\/assets\//)

    await user.keyboard('{Enter}')
    await screen.findByRole('menu')
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('menu')).toBeNull()
    expect(trigger).toHaveFocus()
  })

  it('"All reasons" goes to the landing', async () => {
    const user = userEvent.setup()
    render(<AttentionQueueHeader reason="no_owner" count={1} />)
    await user.click(screen.getByRole('button', { name: 'No owner' }))
    await user.click(await screen.findByRole('menuitem', { name: 'All reasons' }))
    expect(state.push).toHaveBeenCalledWith('/assets/attention')
  })

  it('leaves out a reason whose module is off', async () => {
    state.hidden = ['relationships']
    const user = userEvent.setup()
    render(<AttentionQueueHeader reason="no_owner" count={1} />)
    await user.click(screen.getByRole('button', { name: 'No owner' }))
    const menu = await screen.findByRole('menu')
    expect(within(menu).queryByText('Relationships')).toBeNull()
    expect(within(menu).getAllByRole('menuitemradio')).toHaveLength(6)
  })

  it('renders no tablist', () => {
    render(<AttentionQueueHeader reason="no_owner" count={1} />)
    expect(screen.queryByRole('tablist')).toBeNull()
  })
})
