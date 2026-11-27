import axe from 'axe-core'
import { describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { FindingsEmptyState } from '../findings-empty-state'

const base = {
  filterCount: 0,
  hasSearch: false,
  canImport: true,
  canRunScan: true,
  canOpenIntegrations: true,
  onImport: vi.fn(),
  onClearFilters: vi.fn(),
}

/** The filled (ink) buttons and links of the state: the kit's default variant. */
const filled = () =>
  Array.from(
    screen.getByTestId('findings-empty-state').querySelectorAll('[data-slot=button]')
  ).filter((b) => b.className.includes('bg-primary'))

describe('FindingsEmptyState', () => {
  it('first run: Run a scan is the one filled action, then Import results and Connect a tool', () => {
    const onImport = vi.fn()
    render(<FindingsEmptyState {...base} kind="nothing" onImport={onImport} />)
    expect(screen.getByTestId('findings-empty-state')).toHaveAttribute('data-kind', 'nothing')
    expect(screen.getByText('No findings yet')).toBeInTheDocument()
    const scan = screen.getByRole('link', { name: 'Run a scan' })
    expect(scan).toHaveAttribute('href', '/scans?new=scan')
    fireEvent.click(screen.getByRole('button', { name: 'Import results' }))
    expect(onImport).toHaveBeenCalled()
    expect(screen.getByRole('link', { name: 'Connect a tool' })).toHaveAttribute(
      'href',
      '/settings/integrations'
    )
    expect(filled()).toEqual([scan])
  })

  it('first run: without the scan permission Import results is the filled action', () => {
    render(<FindingsEmptyState {...base} kind="nothing" canRunScan={false} />)
    expect(screen.queryByRole('link', { name: 'Run a scan' })).not.toBeInTheDocument()
    expect(filled()).toEqual([screen.getByRole('button', { name: 'Import results' })])
  })

  it('first run: no import button without the import permission', () => {
    render(<FindingsEmptyState {...base} kind="nothing" canImport={false} />)
    expect(screen.queryByRole('button', { name: /import results/i })).not.toBeInTheDocument()
  })

  it('first run: no link to a page the viewer cannot open, the sentence stays', () => {
    render(
      <FindingsEmptyState
        {...base}
        kind="nothing"
        canImport={false}
        canRunScan={false}
        canOpenIntegrations={false}
      />
    )
    expect(screen.getByText('No findings yet')).toBeInTheDocument()
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('no control of a state carries a page-set height', () => {
    render(<FindingsEmptyState {...base} kind="nothing" />)
    for (const b of screen
      .getByTestId('findings-empty-state')
      .querySelectorAll('[data-slot=button]')) {
      // The kit's default size: 32, 36 on a phone.
      expect(b.className).toContain('h-control ')
      expect(b.className).not.toContain('h-control-dense')
    }
  })

  it('no match: counts what the filters and the search hide, and clears them', () => {
    const onClearFilters = vi.fn()
    const onSearchAllStates = vi.fn()
    render(
      <FindingsEmptyState
        {...base}
        kind="no_match"
        hiddenCount={1204}
        stateLabel="Open"
        filterCount={2}
        hasSearch
        onClearFilters={onClearFilters}
        onSearchAllStates={onSearchAllStates}
      />
    )
    expect(
      screen.getByText('1,204 open findings are hidden by 2 filters and your search.')
    ).toBeInTheDocument()
    const clear = screen.getByRole('button', { name: 'Clear filters' })
    fireEvent.click(clear)
    expect(onClearFilters).toHaveBeenCalled()
    // The control is the State lens: the action names states, not statuses.
    fireEvent.click(screen.getByRole('button', { name: 'Search all states' }))
    expect(onSearchAllStates).toHaveBeenCalled()
    expect(filled()).toEqual([clear])
  })

  it('no match: one filter reads in the singular, search alone offers to clear the search', () => {
    const { rerender } = render(
      <FindingsEmptyState
        {...base}
        kind="no_match"
        hiddenCount={3}
        stateLabel="Open"
        filterCount={1}
      />
    )
    expect(screen.getByText('3 open findings are hidden by 1 filter.')).toBeInTheDocument()
    rerender(<FindingsEmptyState {...base} kind="no_match" hasSearch />)
    expect(screen.getByRole('button', { name: 'Clear search' })).toBeInTheDocument()
  })

  it('no access: says the viewer cannot read findings, with one action to the dashboard', () => {
    render(<FindingsEmptyState {...base} kind="no_access" />)
    expect(screen.getByTestId('findings-empty-state')).toHaveAttribute('data-kind', 'no_access')
    expect(screen.getByText('You cannot read findings here')).toBeInTheDocument()
    expect(screen.queryByText(/scoped/i)).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Go to the dashboard' })).toHaveAttribute('href', '/')
    // One action: no request for access, no import, no scan.
    expect(screen.getAllByRole('link')).toHaveLength(1)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(screen.queryByText(/request access/i)).not.toBeInTheDocument()
  })

  it('no access: names what is missing when the server said so', () => {
    render(
      <FindingsEmptyState
        {...base}
        kind="no_access"
        denial="You need the permission findings:read."
      />
    )
    expect(screen.getByText('You need the permission findings:read.')).toBeInTheDocument()
  })

  it('a practice with nothing yet offers the import only', () => {
    render(<FindingsEmptyState {...base} kind="practice_nothing" practice="compliance" />)
    expect(screen.getByText('No benchmark checks yet')).toBeInTheDocument()
    expect(filled()).toEqual([screen.getByRole('button', { name: 'Import results' })])
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
  })

  it.each(['nothing', 'no_match', 'no_access'] as const)(
    '%s has no accessibility violations',
    async (kind) => {
      const { container } = render(
        <FindingsEmptyState
          {...base}
          kind={kind}
          filterCount={1}
          hiddenCount={5}
          stateLabel="Open"
        />
      )
      const res = await axe.run(container, {
        rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
      })
      expect(res.violations.map((v) => v.id)).toEqual([])
    }
  )
})
