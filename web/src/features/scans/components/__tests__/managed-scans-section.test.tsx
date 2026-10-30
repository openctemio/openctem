/**
 * The scans the platform runs itself (continuous coverage) are listed
 * read-only under the Scans table, with a link to the coverage settings and
 * to their runs. The section asks the same list for origin=system and shows
 * nothing when the tenant has none.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'

import { ManagedScansSection } from '../managed-scans-section'

const calls: Array<Record<string, unknown> | undefined> = []
let response: unknown

vi.mock('@/lib/api/scan-hooks', () => ({
  useScanConfigs: (filters?: Record<string, unknown>) => {
    calls.push(filters)
    return { data: response, isLoading: false }
  },
}))

describe('ManagedScansSection', () => {
  beforeEach(() => {
    calls.length = 0
    response = undefined
  })

  it('shows nothing when no scan is managed', () => {
    response = { data: [], total: 0 }
    const { container } = render(<ManagedScansSection />)
    expect(container).toBeEmptyDOMElement()
    expect(calls.at(-1)).toMatchObject({ origin: 'system' })
  })

  it('lists the managed scans read-only with links to settings and runs', () => {
    response = {
      data: [
        {
          id: 'cov1',
          name: 'Continuous coverage: resolve.dns',
          last_run_id: 'r1',
          last_run_at: '2026-10-27T10:00:00Z',
          last_run_status: 'completed',
        },
      ],
      total: 1,
    }
    render(<ManagedScansSection />)
    expect(
      screen.getByRole('heading', { name: 'Managed by continuous coverage' })
    ).toBeInTheDocument()
    const list = screen.getByTestId('managed-scans-list')
    expect(
      within(list).getByRole('link', { name: 'Continuous coverage: resolve.dns' })
    ).toHaveAttribute('href', '/scans/cov1')
    expect(screen.getByRole('link', { name: 'Open coverage settings' })).toHaveAttribute(
      'href',
      '/settings/scope'
    )
    expect(screen.getByRole('link', { name: 'View their runs' })).toHaveAttribute(
      'href',
      '/scans/runs?origin=system'
    )
    // Read-only: no way to edit, run or schedule from here.
    expect(screen.queryByRole('button')).toBeNull()
  })
})
