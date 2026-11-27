/**
 * Needs attention landing: three groups in a fixed order, one link per reason,
 * count and unit from the queue's own endpoint, zero kept and muted, and a
 * reason the reader cannot open is not listed.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'

const state = vi.hoisted(() => ({
  hidden: [] as string[],
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
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useVisibleSectionTabs: (rows: { module: string }[]) =>
    rows.filter((r) => !state.hidden.includes(r.module)),
}))
vi.mock('../use-attention-count', () => ({
  useAttentionCount: (id: string) => state.counts[id],
}))

import { AttentionReasons } from '../attention-reasons'

beforeEach(() => {
  state.hidden = []
  state.counts = {
    validate_primary: 2,
    decide_monitoring: 0,
    no_owner: 549,
    context: 1,
    unscanned: 0,
    relationships: 12,
    duplicates: 3,
  }
})

describe('AttentionReasons', () => {
  it('lists the reasons in three groups, in a fixed order, each a link to its queue', () => {
    render(<AttentionReasons />)
    const groups = screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)
    expect(groups).toEqual(['Scoping decisions', 'Fix on the asset', 'Review'])
    const hrefs = screen.getAllByRole('link').map((a) => a.getAttribute('href'))
    expect(hrefs).toEqual([
      '/assets/attention/validate-primary',
      '/assets/attention/decide-monitoring',
      '/assets/attention/no-owner',
      '/assets/attention/context',
      '/assets/attention/unscanned',
      '/assets/suggestions',
      '/assets/duplicates',
    ])
    const fix = within(screen.getByRole('region', { name: 'Fix on the asset' }))
    expect(fix.getAllByRole('link')).toHaveLength(3)
  })

  it('shows the count with its unit and the one-line why', () => {
    render(<AttentionReasons />)
    expect(screen.getByTestId('attention-count-no_owner')).toHaveTextContent('549 assets')
    expect(screen.getByTestId('attention-count-context')).toHaveTextContent('1 asset')
    expect(screen.getByTestId('attention-count-relationships')).toHaveTextContent('12 to review')
    expect(screen.getByTestId('attention-count-duplicates')).toHaveTextContent('3 pairs')
    expect(
      screen.getByText('Findings on these assets have nobody to assign to.')
    ).toBeInTheDocument()
  })

  it('keeps a zero row, muted, with "Nothing to do here."', () => {
    render(<AttentionReasons />)
    const row = screen.getByTestId('attention-reason-unscanned')
    expect(row).toHaveTextContent('Nothing to do here.')
    expect(screen.getByTestId('attention-count-unscanned')).toHaveTextContent('0 assets')
    expect(screen.getByTestId('attention-count-unscanned').className).toContain(
      'text-muted-foreground'
    )
  })

  it('shows no number while a count is loading', () => {
    state.counts = {}
    render(<AttentionReasons />)
    expect(screen.getByTestId('attention-count-no_owner')).toHaveTextContent('')
  })

  it('hides Relationships when its module is off, leaving six reasons', () => {
    state.hidden = ['relationships']
    render(<AttentionReasons />)
    expect(screen.getAllByRole('link')).toHaveLength(6)
    expect(screen.queryByText('Relationships')).toBeNull()
  })

  it('lists Decide monitoring as a scoping decision with its why and count', () => {
    state.counts.decide_monitoring = 462
    render(<AttentionReasons />)
    const decide = within(screen.getByRole('region', { name: 'Scoping decisions' }))
    const row = decide.getByTestId('attention-reason-decide_monitoring')
    expect(row).toHaveAttribute('href', '/assets/attention/decide-monitoring')
    expect(row).toHaveTextContent('Decide monitoring')
    expect(row).toHaveTextContent(
      'Discovered names waiting for a decision: monitor, watch only, or not yours.'
    )
    expect(screen.getByTestId('attention-count-decide_monitoring')).toHaveTextContent('462 assets')
  })

  it('renders no tablist: the page keeps one tab row', () => {
    render(<AttentionReasons />)
    expect(screen.queryByRole('tablist')).toBeNull()
    expect(screen.queryByRole('navigation')).toBeNull()
  })
})
