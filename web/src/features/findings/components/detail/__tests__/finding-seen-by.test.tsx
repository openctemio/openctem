/**
 * The finding page's "Seen by" section: one row per source with its tool,
 * sensor and scan linked to the findings that source reported, the last run
 * linked to the run, a backfilled row labelled; absent when nothing reported
 * the finding, hidden on a refusal (no oracle), a Retry row on a failure.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { ApiClientError } from '@/lib/api/error-handler'
import type { FindingSighting } from '../../../api/receipts-api'

let mockData: { data: FindingSighting[] } | undefined
let mockError: unknown
const retry = vi.fn()

vi.mock('../../../api/receipts-api', async (orig) => ({
  ...(await orig<typeof import('../../../api/receipts-api')>()),
  useFindingSightings: () => ({
    data: mockData,
    error: mockError,
    isLoading: false,
    mutate: retry,
  }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't' } }),
  useCurrentTenantId: () => 't',
}))

const { FindingSeenBy } = await import('../finding-seen-by')

function sighting(over: Partial<FindingSighting> = {}): FindingSighting {
  return {
    channel: 'scan',
    tool: 'nuclei',
    tool_version: '3.4.1',
    first_seen_at: '2026-11-01T00:00:00Z',
    last_seen_at: '2026-11-04T00:00:00Z',
    seen_count: 3,
    backfilled: false,
    ...over,
  } as FindingSighting
}

describe('FindingSeenBy', () => {
  beforeEach(() => {
    mockData = undefined
    mockError = undefined
  })

  it('links the scan, tool, sensor and last run of each source', () => {
    mockData = {
      data: [
        sighting({
          scan: { id: 'scan-1', name: 'Weekly external' },
          sensor: { id: 'sensor-1', name: 'edge-1' },
          run_id: 'run-1',
        }),
        sighting({
          channel: 'ci',
          sender: 'github.com/acme/app',
          tool: 'semgrep',
          tool_version: '',
        }),
      ],
    }
    render(<FindingSeenBy findingId="f-1" />)
    const list = screen.getByTestId('finding-seen-by')
    expect(within(list).getAllByRole('listitem')).toHaveLength(2)
    expect(screen.getByRole('link', { name: 'Weekly external' })).toHaveAttribute(
      'href',
      '/findings?seen_by_scan_id=scan-1&state=all'
    )
    expect(screen.getByRole('link', { name: 'nuclei 3.4.1' })).toHaveAttribute(
      'href',
      '/findings?seen_by_tool=nuclei&state=all'
    )
    expect(screen.getByRole('link', { name: 'edge-1' })).toHaveAttribute(
      'href',
      '/findings?seen_by_sensor_id=sensor-1&state=all'
    )
    expect(screen.getByRole('link', { name: 'Last run' })).toHaveAttribute(
      'href',
      '/scans/runs?run=run-1'
    )
    expect(screen.getByText('github.com/acme/app')).toBeInTheDocument()
    expect(screen.getAllByText('3 times')).toHaveLength(2)
  })

  it('labels a backfilled source and a shared platform sensor without an id', () => {
    mockData = { data: [sighting({ channel: 'sensor', sender: 'platform', backfilled: true })] }
    render(<FindingSeenBy findingId="f-1" />)
    expect(screen.getByText('From earlier records')).toBeInTheDocument()
    expect(screen.getByText('Platform sensor')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /sensor/i })).toBeNull()
  })

  it('is absent when nothing reported the finding, and on a refusal', () => {
    mockData = { data: [] }
    const { container, rerender } = render(<FindingSeenBy findingId="f-1" />)
    expect(container).toBeEmptyDOMElement()
    mockData = undefined
    mockError = new ApiClientError('not found', 'NOT_FOUND', 404)
    rerender(<FindingSeenBy findingId="f-1" />)
    expect(container).toBeEmptyDOMElement()
  })
})
