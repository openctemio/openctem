import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { PageStack } from '../page-stack'
import { PageHeader } from '../page-header'
import { SectionTabs } from '../section-tabs'
import { ListToolbar } from '../list-toolbar'
import { MetricStrip, METRIC_STRIP_MAX } from '../metric-strip'

vi.mock('next/navigation', () => ({ usePathname: () => '/scans/runs' }))

/**
 * Page anatomy primitives (research/244). jsdom does not lay out, so these
 * pin the contract the Playwright rhythm check (web/e2e/specs/31-page-rhythm)
 * measures in a browser: who owns each gap, and the hooks it relies on.
 */
describe('PageStack', () => {
  it('owns the gap between blocks and zeroes the blocks own margins', () => {
    render(
      <PageStack data-testid="stack">
        <div className="mt-5">block</div>
      </PageStack>
    )
    const stack = screen.getByTestId('stack')
    expect(stack).toHaveAttribute('data-slot', 'page-stack')
    expect(stack).toHaveClass('flex', 'flex-col', 'gap-page', '[&>*]:my-0!')
  })

  it('pulls the tab strip to the tight gap only right under the page header', () => {
    render(
      <PageStack data-testid="stack">
        <PageHeader title="Scans" />
        <SectionTabs
          label="Scans sections"
          tabs={[
            { label: 'Scans', href: '/scans' },
            { label: 'Runs', href: '/scans/runs' },
          ]}
        />
      </PageStack>
    )
    const stack = screen.getByTestId('stack')
    expect(stack.className).toContain('[&>[data-slot=page-header]+[data-slot=page-tabs]]:-mt-1!')
    expect(stack.className).toContain('[&>[data-slot=page-header]+[data-slot=tabs]]:-mt-1!')
    const header = stack.firstElementChild as HTMLElement
    const tabs = screen.getByRole('navigation', { name: 'Scans sections' })
    expect(header).toHaveAttribute('data-slot', 'page-header')
    expect(tabs).toHaveAttribute('data-slot', 'page-tabs')
    expect(header.nextElementSibling).toBe(tabs)
  })

  it('gives inline Radix tabs directly in the stack the page gap', () => {
    render(<PageStack data-testid="stack" />)
    expect(screen.getByTestId('stack').className).toContain('[&>[data-slot=tabs]]:gap-page')
  })
})

describe('ListToolbar', () => {
  it('renders search, filter tokens and end in that order, end pushed to the far side', () => {
    render(
      <ListToolbar
        search={{ value: '', onChange: () => {}, placeholder: 'Search…', label: 'Search' }}
        start={<button type="button">Status</button>}
        end={<button type="button">View</button>}
      />
    )
    const bar = screen.getByTestId('data-table-toolbar')
    expect(bar).toHaveAttribute('data-slot', 'list-toolbar')
    const order = [...bar.querySelectorAll('button, input')].map(
      (el) => el.textContent || el.getAttribute('aria-label')
    )
    expect(order).toEqual(['Search', 'Status', 'View'])
    expect(screen.getByText('View').parentElement).toHaveClass('ms-auto')
  })

  it('renders no empty groups', () => {
    render(<ListToolbar search={{ value: '', onChange: () => {}, placeholder: 'Search…' }} />)
    const bar = screen.getByTestId('data-table-toolbar')
    expect(bar.children).toHaveLength(1)
  })
})

describe('MetricStrip anatomy', () => {
  afterEach(() => vi.restoreAllMocks())

  it('is two columns on a phone with no sideways scroll, an odd last tile spanning the row', () => {
    render(
      <MetricStrip
        items={[
          { key: 'a', label: 'A', value: 1, onClick: () => {} },
          { key: 'b', label: 'B', value: 2, onClick: () => {} },
          { key: 'c', label: 'C', value: 3, onClick: () => {} },
        ]}
      />
    )
    const dl = document.querySelector('[data-slot=metric-strip]') as HTMLElement
    // Phone: a six-track grid, three tiles in thirds, one row.
    expect(dl).toHaveClass('grid', 'grid-cols-6')
    expect(dl.className).not.toMatch(/overflow-x-auto|snap-x/)
    for (const tile of Array.from(dl.children)) expect(tile).toHaveClass('col-span-2')
  })

  it('makes an href tile a link that marks the current list', () => {
    render(
      <MetricStrip
        items={[
          { key: 'f', label: 'Failed', value: 4, href: '/scans/runs?status=failed', active: true },
        ]}
      />
    )
    const link = screen.getByRole('link', { name: /failed/i })
    expect(link).toHaveAttribute('href', '/scans/runs?status=failed')
    expect(link).toHaveAttribute('aria-current', 'page')
    expect(link).toHaveClass('bg-accent')
  })

  it('shows a zero as a muted 0, never hidden and never red', () => {
    render(
      <MetricStrip
        items={[{ key: 'f', label: 'Failed', value: 0, tone: 'danger', onClick: () => {} }]}
      />
    )
    const zero = screen.getByText('0')
    expect(zero).toHaveClass('text-muted-foreground')
    expect(zero).not.toHaveClass('text-destructive')
  })

  it('keeps its place on error with a dash per value and the reason as tooltip', () => {
    render(
      <MetricStrip
        error="Could not load the numbers"
        items={[{ key: 'f', label: 'Failed', value: 4, onClick: () => {} }]}
      />
    )
    expect(screen.getByText('Failed')).toBeInTheDocument()
    expect(screen.queryByText('4')).not.toBeInTheDocument()
    expect(screen.getByText('—')).toHaveAttribute('title', 'Could not load the numbers')
  })

  it('warns in development when a page asks for more tiles than the anatomy allows', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const items = Array.from({ length: METRIC_STRIP_MAX + 1 }, (_, i) => ({
      key: String(i),
      label: `M${i}`,
      value: i,
      onClick: () => {},
    }))
    render(<MetricStrip items={items} />)
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('research/244'))
  })
})
