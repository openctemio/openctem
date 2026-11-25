import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useRouter, useSearchParams } from 'next/navigation'
import { receiptListUrl } from '../../api/receipts-api'
import { ReceiptHistory, receiptFiltersOf } from '../receipt-history'

const swr = vi.hoisted(() => ({
  key: '' as string | null,
  data: undefined as unknown,
  error: undefined as unknown,
}))

vi.mock('@/context/tenant-provider', () => ({ useCurrentTenantId: () => 't1' }))
// The retired sources section has its own tests (source-retirement).
vi.mock('../source-retirement', () => ({ RetiredSourcesSection: () => null }))
vi.mock('../import-results-dialog', () => ({ ImportResultsDialog: () => null }))
const perms = vi.hoisted(() => ({ granted: true }))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => perms.granted }),
}))
vi.mock('swr', () => ({
  default: (key: string | null) => {
    swr.key = key
    return { data: swr.data, error: swr.error, isLoading: false, mutate: vi.fn() }
  },
}))

describe('receiptFiltersOf', () => {
  it('keeps only the filters the list accepts, with valid values', () => {
    expect(
      receiptFiltersOf(
        new URLSearchParams('origin=sensor&tool=nuclei&since=2026-09-26T00:00:00Z&page=2&x=1')
      )
    ).toEqual({
      sourceKind: undefined,
      origin: 'sensor',
      tool: 'nuclei',
      since: '2026-09-26T00:00:00Z',
      page: 2,
      perPage: 50,
    })
    // A value the API would refuse never reaches it.
    expect(
      receiptFiltersOf(new URLSearchParams('origin=upload&since=yesterday&page=-1&source_kind=x'))
    ).toEqual({
      sourceKind: undefined,
      origin: undefined,
      tool: undefined,
      since: undefined,
      page: undefined,
      perPage: 50,
    })
  })

  it('builds the same request the dashboard figure was counted with', () => {
    expect(receiptListUrl({ origin: 'ci', tool: 'unknown', since: '2026-09-26T00:00:00Z' })).toBe(
      '/api/v1/findings/imports?origin=ci&tool=unknown&since=2026-09-26T00%3A00%3A00Z'
    )
  })
})

describe('ReceiptHistory', () => {
  const replace = vi.fn()
  beforeEach(() => {
    replace.mockClear()
    vi.mocked(useRouter).mockReturnValue({ replace, push: vi.fn() } as unknown as ReturnType<
      typeof useRouter
    >)
    vi.mocked(useSearchParams).mockReturnValue(
      new URLSearchParams(
        'origin=sensor&tool=nuclei&since=2026-09-26T00:00:00Z'
      ) as unknown as ReturnType<typeof useSearchParams>
    )
    swr.error = undefined
    swr.data = {
      data: [
        {
          id: 'r1',
          status: 'completed',
          source: { kind: 'scan_run', ref: 'run-1' },
          tool: 'nuclei',
          received: 100,
          counts: {
            created: 20,
            updated: 70,
            reactivated: 2,
            closed: 0,
            skipped: 3,
            failed: 0,
            suppressed: 4,
          },
          started_at: '2026-10-25T10:00:00Z',
        },
      ],
      total: 3,
      page: 1,
      per_page: 50,
      total_pages: 1,
      totals: {
        receipts: 3,
        received: 190,
        created: 27,
        updated: 148,
        reactivated: 2,
        closed: 0,
        skipped: 3,
        failed: 0,
        suppressed: 4,
      },
    }
  })

  it('puts the totals after the list at every width (list first)', () => {
    render(<ReceiptHistory />)
    const section = screen.getByTestId('receipt-totals').closest('section')
    expect(section).toHaveClass('order-last')
    expect(section).not.toHaveClass('md:order-none')
  })

  it('shows the totals of the filter (the dashboard figure) and the filters as removable chips', async () => {
    render(<ReceiptHistory />)
    expect(swr.key).toBe(
      '/api/v1/findings/imports?origin=sensor&tool=nuclei&since=2026-09-26T00%3A00%3A00Z&per_page=50'
    )
    const totals = screen.getByTestId('receipt-totals')
    expect(within(totals).getByText('190')).toBeInTheDocument()
    expect(screen.getByText('Totals of 3 receipts')).toBeInTheDocument()
    expect(screen.getAllByText('Scan run').length).toBeGreaterThan(0)
    await userEvent.click(screen.getByRole('button', { name: 'Remove tool filter: nuclei' }))
    expect(replace).toHaveBeenCalledWith('/?origin=sensor&since=2026-09-26T00%3A00%3A00Z')
  })

  it('offers Import results only with the import permissions', () => {
    perms.granted = false
    const { unmount } = render(<ReceiptHistory />)
    expect(screen.queryByRole('button', { name: 'Import results' })).not.toBeInTheDocument()
    unmount()
    perms.granted = true
    render(<ReceiptHistory />)
    expect(screen.getAllByRole('button', { name: 'Import results' }).length).toBeGreaterThan(0)
  })

  it('opens a receipt in the side sheet from its row', async () => {
    render(<ReceiptHistory />)
    await userEvent.click(screen.getAllByRole('row')[1])
    expect(await screen.findByText('Receipt 1 of 1')).toBeInTheDocument()
  })

  it('filters by source kind through the URL and the request', async () => {
    vi.mocked(useSearchParams).mockReturnValue(
      new URLSearchParams('source_kind=upload') as unknown as ReturnType<typeof useSearchParams>
    )
    render(<ReceiptHistory />)
    expect(swr.key).toBe('/api/v1/findings/imports?source_kind=upload&per_page=50')
  })

  it('shows the error state when the list cannot be read', () => {
    swr.data = undefined
    swr.error = new Error('boom')
    render(<ReceiptHistory />)
    expect(screen.queryByTestId('receipt-totals')).not.toBeInTheDocument()
    expect(screen.getAllByText(/Import and run receipts/).length).toBeGreaterThan(0)
  })

  it('says there are no receipts yet when no filter is set, and blames filters only when one is', () => {
    swr.data = { ...(swr.data as object), data: [], total: 0, totals: undefined }
    vi.mocked(useSearchParams).mockReturnValue(
      new URLSearchParams('') as unknown as ReturnType<typeof useSearchParams>
    )
    const { unmount } = render(<ReceiptHistory />)
    expect(screen.getByText('No imports yet.')).toBeInTheDocument()
    expect(screen.queryByText('No imports match these filters.')).not.toBeInTheDocument()
    unmount()
    vi.mocked(useSearchParams).mockReturnValue(
      new URLSearchParams('origin=sensor') as unknown as ReturnType<typeof useSearchParams>
    )
    render(<ReceiptHistory />)
    expect(screen.getByText('No imports match these filters.')).toBeInTheDocument()
  })
})
