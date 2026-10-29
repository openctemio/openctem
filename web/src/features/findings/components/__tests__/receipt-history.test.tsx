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
      origin: 'sensor',
      tool: 'nuclei',
      since: '2026-09-26T00:00:00Z',
      page: 2,
      perPage: 50,
    })
    // A value the API would refuse never reaches it.
    expect(receiptFiltersOf(new URLSearchParams('origin=upload&since=yesterday&page=-1'))).toEqual({
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

  it('shows the totals of the filter (the dashboard figure) and the filters as removable chips', async () => {
    render(<ReceiptHistory />)
    expect(swr.key).toBe(
      '/api/v1/findings/imports?origin=sensor&tool=nuclei&since=2026-09-26T00%3A00%3A00Z&per_page=50'
    )
    const totals = screen.getByTestId('receipt-totals')
    expect(within(totals).getByText('190')).toBeInTheDocument()
    expect(screen.getByText('Totals of 3 receipts')).toBeInTheDocument()
    expect(screen.getByText('Scan run')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Remove filter nuclei' }))
    expect(replace).toHaveBeenCalledWith('/?origin=sensor&since=2026-09-26T00%3A00%3A00Z')
  })

  it('shows the error state when the list cannot be read', () => {
    swr.data = undefined
    swr.error = new Error('boom')
    render(<ReceiptHistory />)
    expect(screen.queryByTestId('receipt-totals')).not.toBeInTheDocument()
    expect(screen.getAllByText(/Import and run receipts/).length).toBeGreaterThan(0)
  })
})
