/**
 * The finding page's "Reported by N sources" section: shown when two or more
 * sources reported the finding, the fields they disagree on side by side
 * (one column per source), the primary source marked, each source's own
 * values folded below; absent with one source or on a refusal (no oracle),
 * a Retry row on a failure.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { ApiClientError } from '@/lib/api/error-handler'
import type { FindingSourceRecord, FindingSourcesResponse } from '../../../api/sources-api'

let mockData: FindingSourcesResponse | undefined
let mockError: unknown
const retry = vi.fn()

vi.mock('../../../api/sources-api', async (orig) => ({
  ...(await orig<typeof import('../../../api/sources-api')>()),
  useFindingSources: () => ({ data: mockData, error: mockError, isLoading: false, mutate: retry }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't' } }),
  useCurrentTenantId: () => 't',
}))

const { FindingSourceRecords } = await import('../finding-source-records')

function record(over: Partial<FindingSourceRecord> = {}): FindingSourceRecord {
  return {
    channel: 'upload',
    tool: 'nessus',
    primary: false,
    backfilled: false,
    truncated: false,
    first_seen_at: '2026-11-01T00:00:00Z',
    last_seen_at: '2026-11-04T00:00:00Z',
    ...over,
  }
}

const nessus = record({
  primary: true,
  title: 'OpenSSH regreSSHion',
  severity: 'high',
  description: 'nessus text',
  native: { scheme: 'nessus', vuln_id: '201194', severity: '3' },
  source_extra: { plugin_type: 'remote' },
})
const openvas = record({
  channel: 'scan',
  tool: 'openvas',
  sensor: { id: 's-1', name: 'dc1' },
  title: 'OpenSSH RCE',
  severity: 'critical',
  recommendation: 'Update to 9.8p1.',
  native: { scheme: 'openvas', vuln_id: '1.3.6.1', severity: '8.1' },
})

describe('FindingSourceRecords', () => {
  beforeEach(() => {
    mockData = undefined
    mockError = undefined
    retry.mockReset()
  })

  it('shows the disagreements side by side and each source folded', () => {
    mockData = {
      data: [nessus, openvas],
      differences: [
        { field: 'vendor_severity', values: ['3', '8.1'] },
        { field: 'native_id', values: ['201194', ''] },
      ],
    }
    render(<FindingSourceRecords findingId="f-1" />)
    expect(screen.getByText('Reported by 2 sources')).toBeInTheDocument()
    expect(screen.getByText(/shows what nessus reported first/)).toBeInTheDocument()

    const table = screen.getByTestId('finding-source-differences')
    const vendor = within(table).getByText('Vendor severity').closest('tr') as HTMLElement
    expect(within(vendor).getByText('3')).toBeInTheDocument()
    expect(within(vendor).getByText('8.1')).toBeInTheDocument()
    const nativeRow = within(table).getByText('Source check id').closest('tr') as HTMLElement
    expect(within(nativeRow).getByText('-')).toBeInTheDocument()

    const rows = screen.getAllByTestId('finding-source-record')
    expect(rows).toHaveLength(2)
    expect(within(rows[0]).getByText('Shown on the finding')).toBeInTheDocument()
    expect(within(rows[1]).queryByText('Shown on the finding')).toBeNull()
    expect(within(rows[1]).getByText(/dc1/)).toBeInTheDocument()

    fireEvent.click(within(rows[1]).getByText('What openvas reported'))
    expect(within(rows[1]).getByText('OpenSSH RCE')).toBeInTheDocument()
    expect(within(rows[1]).getAllByText('Update to 9.8p1.').length).toBeGreaterThan(0)
  })

  it('says the sources agree when nothing differs', () => {
    mockData = { data: [nessus, record({ tool: 'openvas' })], differences: [] }
    render(<FindingSourceRecords findingId="f-1" />)
    expect(screen.getByTestId('finding-sources-agree')).toBeInTheDocument()
    expect(screen.queryByTestId('finding-source-differences')).toBeNull()
  })

  it('is absent with one source, and on a refusal', () => {
    mockData = { data: [nessus], differences: [] }
    const { container, rerender } = render(<FindingSourceRecords findingId="f-1" />)
    expect(container).toBeEmptyDOMElement()
    mockData = undefined
    mockError = new ApiClientError('Not found', 'NOT_FOUND', 404)
    rerender(<FindingSourceRecords findingId="f-1" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('offers a retry on a failure', () => {
    mockError = new ApiClientError('boom', 'INTERNAL', 500)
    render(<FindingSourceRecords findingId="f-1" />)
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(retry).toHaveBeenCalled()
  })
})
