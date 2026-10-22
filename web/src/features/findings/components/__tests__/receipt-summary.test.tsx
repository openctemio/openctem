/**
 * Receipts: the counts of an upload or run, what its coverage means, the
 * recent imports, a run's receipt (nothing when the API shows none) and a
 * finding's "last seen in" line.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

import {
  FindingLastSeenIn,
  ReceiptSummary,
  RecentImports,
  RunReceiptSection,
} from '../receipt-summary'
import type { ReceiptResponse } from '../../api/receipts-api'

const getMock = vi.fn()
vi.mock('@/lib/api/client', () => ({ get: (...a: unknown[]) => getMock(...a) }))
vi.mock('@/context/tenant-provider', () => ({ useCurrentTenantId: () => 't1' }))

function wrap(node: ReactNode) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{node}</SWRConfig>
  )
}

const receipt = (over: Partial<ReceiptResponse> = {}): ReceiptResponse =>
  ({
    id: 'r1',
    status: 'completed',
    source: { kind: 'scan_run', ref: 'run-1' },
    coverage: { type: 'full', note: 'resolved' },
    counts: {
      created: 3,
      updated: 5,
      reactivated: 1,
      closed: 2,
      untouched: 4,
      skipped: 0,
      failed: 1,
    },
    started_at: '2026-10-20T10:00:00Z',
    ...over,
  }) as ReceiptResponse

beforeEach(() => getMock.mockReset())

describe('ReceiptSummary', () => {
  it('shows every count and that full coverage could close', () => {
    render(<ReceiptSummary receipt={receipt()} />)
    const box = screen.getByTestId('receipt-summary')
    for (const [label, value] of [
      ['New', '3'],
      ['Still detected', '5'],
      ['Reopened', '1'],
      ['Closed', '2'],
      ['Untouched', '4'],
      ['Failed', '1'],
    ]) {
      expect(screen.getByText(label).nextSibling).toHaveTextContent(value)
    }
    expect(box).toHaveTextContent(/Full coverage/)
  })

  it('shows untouched as unknown under partial coverage, and a held close', () => {
    const { rerender } = render(
      <ReceiptSummary
        receipt={receipt({
          coverage: { type: 'partial' },
          counts: {
            created: 1,
            updated: 0,
            reactivated: 0,
            closed: 0,
            untouched: undefined,
            skipped: 0,
            failed: 0,
          },
        })}
      />
    )
    expect(screen.getByText('Untouched').nextSibling).toHaveTextContent('—')
    expect(screen.getByTestId('receipt-summary')).toHaveTextContent(
      /Partial coverage: it closes nothing/
    )
    rerender(<ReceiptSummary receipt={receipt({ coverage: { type: 'full', note: 'held' } })} />)
    expect(screen.getByTestId('receipt-summary')).toHaveTextContent(/held for review/)
  })
})

describe('RecentImports', () => {
  it('lists the latest uploads', async () => {
    getMock.mockResolvedValueOnce({
      data: [receipt({ id: 'u1', format: 'nessus', source: { kind: 'upload', ref: 'u1' } })],
    })
    wrap(<RecentImports />)
    await waitFor(() =>
      expect(screen.getByTestId('recent-imports')).toHaveTextContent(
        /3 new · 5 still detected · 2 closed/
      )
    )
    expect(getMock.mock.calls[0][0]).toBe('/api/v1/findings/imports?source_kind=upload&per_page=5')
  })
})

describe('RunReceiptSection', () => {
  it('renders the run receipt, and nothing when the API returns none', async () => {
    getMock.mockResolvedValueOnce({ data: [receipt()] })
    const { unmount } = wrap(<RunReceiptSection runId="run-1" />)
    await waitFor(() =>
      expect(screen.getByText('What this run did to findings')).toBeInTheDocument()
    )
    expect(getMock.mock.calls[0][0]).toBe(
      '/api/v1/findings/imports?source_kind=scan_run&source_ref=run-1&per_page=1'
    )
    unmount()
    getMock.mockResolvedValueOnce({ data: [] })
    const { container } = wrap(<RunReceiptSection runId="run-2" />)
    await waitFor(() => expect(getMock).toHaveBeenCalledTimes(2))
    expect(container).toBeEmptyDOMElement()
  })
})

describe('FindingLastSeenIn', () => {
  it('names the newest run and links to it', async () => {
    getMock.mockResolvedValueOnce({
      data: [
        {
          receipt_id: 'r1',
          source: { kind: 'scan_run', ref: 'run-9' },
          tool: 'nuclei',
          action: 'still_detected',
          at: '2026-10-20T10:00:00Z',
        },
      ],
    })
    wrap(<FindingLastSeenIn findingId="f1" />)
    const line = await screen.findByTestId('finding-last-seen-in')
    expect(line).toHaveTextContent(/Scan run/)
    expect(line).toHaveTextContent(/still detected it/)
    expect(screen.getByRole('link', { name: 'Scan run' })).toHaveAttribute(
      'href',
      '/scans/runs?run=run-9'
    )
    expect(getMock.mock.calls[0][0]).toBe('/api/v1/findings/f1/imports')
  })

  it('shows a dash when nothing acted on the finding', async () => {
    getMock.mockResolvedValueOnce({ data: [] })
    wrap(<FindingLastSeenIn findingId="f2" />)
    await waitFor(() => expect(getMock).toHaveBeenCalled())
    expect(screen.getByText('—')).toBeInTheDocument()
  })
})
