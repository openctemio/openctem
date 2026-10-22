import axe from 'axe-core'
import { describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { FindingsEmptyState } from '../findings-empty-state'

const base = {
  filterCount: 0,
  hasSearch: false,
  canImport: true,
  canSetUpScan: true,
  canOpenIntegrations: true,
  onImport: vi.fn(),
  onClearFilters: vi.fn(),
}

describe('FindingsEmptyState', () => {
  it('nothing yet: says so and offers import, a scan and integrations', () => {
    const onImport = vi.fn()
    render(<FindingsEmptyState {...base} kind="nothing" onImport={onImport} />)
    expect(screen.getByText('No findings in this organization yet')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /import results/i }))
    expect(onImport).toHaveBeenCalled()
    expect(screen.getByRole('link', { name: /set up a scan/i })).toHaveAttribute('href', '/scans')
    expect(screen.getByRole('link', { name: /integrations/i })).toHaveAttribute(
      'href',
      '/settings/integrations'
    )
  })

  it('nothing yet: no import button without the import permission', () => {
    render(<FindingsEmptyState {...base} kind="nothing" canImport={false} />)
    expect(screen.queryByRole('button', { name: /import results/i })).not.toBeInTheDocument()
  })

  it('nothing yet: no link to a page the viewer cannot open', () => {
    render(
      <FindingsEmptyState
        {...base}
        kind="nothing"
        canSetUpScan={false}
        canOpenIntegrations={false}
      />
    )
    expect(screen.queryByRole('link', { name: /set up a scan/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /integrations/i })).not.toBeInTheDocument()
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
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(onClearFilters).toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Search all statuses' }))
    expect(onSearchAllStates).toHaveBeenCalled()
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

  it('no access: names what is missing when the server said so, with no actions that cannot help', () => {
    render(
      <FindingsEmptyState
        {...base}
        kind="no_access"
        denial="You need the permission findings:read."
      />
    )
    expect(screen.getByText('You do not have access to these findings')).toBeInTheDocument()
    expect(screen.getByText('You need the permission findings:read.')).toBeInTheDocument()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
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
