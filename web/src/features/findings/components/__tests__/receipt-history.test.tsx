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
vi.mock('@/context/bootstrap-provider', () => ({
  useBootstrapModules: () => ({ hasModule: () => true }),
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

  const noFindings = (id: string, hoursAgo: number) => ({
    id,
    status: 'completed',
    source: { kind: 'scan_run', ref: id },
    tool: 'subfinder',
    received: 0,
    counts: {
      created: 0,
      updated: 0,
      reactivated: 0,
      closed: 0,
      skipped: 0,
      failed: 0,
      suppressed: 0,
    },
    assets: { created: 2, updated: 3, recorded_on_name: 0 },
    errors: [],
    started_at: new Date(Date.parse('2026-10-25T10:00:00Z') - hoursAgo * 3600_000).toISOString(),
    updated_at: new Date(Date.parse('2026-10-25T10:05:00Z') - hoursAgo * 3600_000).toISOString(),
  })
  const withMix = () => {
    const base = swr.data as { data: object[] }
    swr.data = {
      ...base,
      data: [
        ...base.data,
        noFindings('s1', 1),
        noFindings('s2', 2),
        { ...noFindings('f1', 3), tool: 'nuclei', status: 'failed' },
        noFindings('s3', 4),
      ],
    }
  }

  it('says what each receipt changed in words and shows a status only when it needs a look', () => {
    withMix()
    render(<ReceiptHistory />)
    expect(
      screen.getAllByText('20 new, 2 reopened, 4 closed by a rule, 3 not stored').length
    ).toBeGreaterThan(0)
    expect(screen.queryByText('Completed')).not.toBeInTheDocument()
    expect(screen.getAllByText('Failed').length).toBeGreaterThan(0)
    // The six count columns start hidden (Display > Columns has them).
    expect(screen.queryByRole('columnheader', { name: 'Still detected' })).not.toBeInTheDocument()
  })

  it('folds the runs that received no findings into one row that opens every run', async () => {
    withMix()
    render(<ReceiptHistory />)
    // r1, the folded subfinder runs, the failed run: three rows (plus the header).
    expect(screen.getAllByRole('row')).toHaveLength(4)
    const folded = screen.getAllByText('3 runs, no findings, 15 assets found')
    await userEvent.click(folded[0])
    const runs = await screen.findByTestId('receipt-group-runs')
    expect(within(runs).getAllByRole('button')).toHaveLength(3)
    const link = screen.getByRole('link', { name: 'See the asset changes' })
    expect(link.getAttribute('href')).toMatch(/^\/attack-surface\/changes\?from=.+&to=.+/)
    await userEvent.click(within(runs).getAllByRole('button')[0])
    expect(await screen.findByText('What this run did')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open the run' })).toHaveAttribute(
      'href',
      '/scans/runs?run=s1'
    )
    await userEvent.click(screen.getByRole('button', { name: 'Back to the runs with no findings' }))
    expect(await screen.findByTestId('receipt-group-runs')).toBeInTheDocument()
  })

  it('puts the context chips in the toolbar row, not a row of their own', () => {
    render(<ReceiptHistory />)
    const chip = screen.getByRole('button', { name: 'Remove tool filter: nuclei' })
    expect(chip.closest('[data-slot="list-toolbar-start"]')).not.toBeNull()
    expect(chip.closest('[data-slot="list-toolbar-below"]')).toBeNull()
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
    expect(screen.getByText('Totals of 3 imports')).toBeInTheDocument()
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
    expect(await screen.findByText('Import 1 of 1')).toBeInTheDocument()
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
    expect(screen.getAllByText(/Imports/).length).toBeGreaterThan(0)
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
