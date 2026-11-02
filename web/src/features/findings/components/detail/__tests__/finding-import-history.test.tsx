/**
 * The finding page's import history: every upload or run that acted on the
 * finding, newest first, with what it did; the first rows with "Show all";
 * absent for a finding nothing reported, hidden on a refusal (no oracle),
 * a Retry row on a failure. The header carries the KEV chip.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ApiClientError } from '@/lib/api/error-handler'
import type { FindingReceipt } from '../../../api/receipts-api'
import type { FindingDetail } from '../../../types'

let mockData: { data: FindingReceipt[] } | undefined
let mockError: unknown
let lastFindingId: string | undefined
const retry = vi.fn()

vi.mock('../../../api/receipts-api', async (orig) => ({
  ...(await orig<typeof import('../../../api/receipts-api')>()),
  useFindingReceipts: (id: string | undefined) => {
    lastFindingId = id
    return { data: mockData, error: mockError, isLoading: false, mutate: retry }
  },
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
  usePathname: () => '/',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useCanMutate: () => false,
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => false,
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => false }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't' } }),
  useCurrentTenantId: () => 't',
}))
vi.mock('@/features/ai-triage/components', () => ({ AITriageButton: () => null }))
vi.mock('../../create-ticket-dialog', () => ({ CreateTicketDialog: () => null }))
vi.mock('../../mark-duplicate-dialog', () => ({ MarkDuplicateDialog: () => null }))
vi.mock('../../../hooks/use-can-create-ticket', () => ({ useCanCreateTicket: () => false }))
vi.mock('@/features/remediation-hub/components/add-findings-to-task-dialog', () => ({
  AddFindingsToTaskDialog: () => null,
}))

const { FindingImportHistory, IMPORT_HISTORY_PREVIEW } = await import('../finding-import-history')
const { FindingHeader } = await import('../finding-header')

function receipt(n: number, over: Partial<FindingReceipt> = {}): FindingReceipt {
  return {
    receipt_id: `r-${n}`,
    source: { kind: 'upload', ref: '' },
    tool: 'nuclei',
    action: 'still_detected',
    at: new Date(Date.now() - n * 3_600_000).toISOString(),
    ...over,
  } as FindingReceipt
}

beforeEach(() => {
  mockData = undefined
  mockError = undefined
  lastFindingId = undefined
  retry.mockReset()
})

describe('FindingImportHistory', () => {
  it('lists what each upload or run did, newest first, for this finding', () => {
    mockData = {
      data: [
        receipt(1, { source: { kind: 'scan_run', ref: 'run/1 2' }, action: 'reopened' }),
        receipt(2, { action: 'closed', tool: 'trivy' }),
        receipt(3, { action: 'created' }),
      ],
    }
    render(<FindingImportHistory findingId="f-1" />)
    expect(lastFindingId).toBe('f-1')
    const section = screen.getByRole('region', { name: /Import history/ })
    const rows = within(section).getAllByRole('listitem')
    expect(rows).toHaveLength(3)
    expect(rows[0]).toHaveTextContent('Scan run')
    expect(rows[0]).toHaveTextContent('Reopened')
    expect(rows[1]).toHaveTextContent('Import')
    expect(rows[1]).toHaveTextContent('trivy')
    expect(rows[1]).toHaveTextContent('Resolved')
    expect(rows[2]).toHaveTextContent('New')
    // A run's receipt opens that run; the reference is encoded, never raw.
    expect(within(rows[0]).getByRole('link', { name: 'Scan run' })).toHaveAttribute(
      'href',
      '/scans/runs?run=run%2F1%202'
    )
    expect(within(rows[1]).queryByRole('link')).not.toBeInTheDocument()
  })

  it('names every action the API records, never mislabels a rule decision', () => {
    mockData = {
      data: [
        receipt(1, { action: 'suppressed' }),
        receipt(2, { action: 'held' }),
        receipt(3, { action: 'still_detected' }),
      ],
    }
    render(<FindingImportHistory findingId="f-1" />)
    const chips = screen.getAllByText(/./, { selector: '[data-slot="import-history-action"]' })
    expect(chips.map((c) => c.textContent)).toEqual([
      'Suppressed by a rule',
      'Held for review',
      'Still detected',
    ])
  })

  it('shows the first rows and the rest on "Show all"', async () => {
    mockData = { data: Array.from({ length: 7 }, (_, i) => receipt(i + 1)) }
    render(<FindingImportHistory findingId="f-1" />)
    expect(screen.getAllByRole('listitem')).toHaveLength(IMPORT_HISTORY_PREVIEW)
    const more = screen.getByRole('button', { name: 'Show all 7' })
    expect(more).toHaveAttribute('aria-expanded', 'false')
    await userEvent.click(more)
    expect(screen.getAllByRole('listitem')).toHaveLength(7)
    await userEvent.click(screen.getByRole('button', { name: 'Show fewer' }))
    expect(screen.getAllByRole('listitem')).toHaveLength(IMPORT_HISTORY_PREVIEW)
  })

  it('has no "Show all" when every row fits', () => {
    mockData = { data: [receipt(1), receipt(2)] }
    render(<FindingImportHistory findingId="f-1" />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('is absent for a finding no upload or run reported', () => {
    mockData = { data: [] }
    const { container } = render(<FindingImportHistory findingId="f-1" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('stays hidden on a refusal: a finding outside the data scope answers 404', () => {
    for (const status of [403, 404]) {
      mockError = new ApiClientError('x', 'X', status)
      const { container, unmount } = render(<FindingImportHistory findingId="f-other" />)
      expect(container).toBeEmptyDOMElement()
      unmount()
    }
  })

  it('a failed read shows a Retry row, not an empty history', async () => {
    mockError = new ApiClientError('boom', 'INTERNAL', 500)
    render(<FindingImportHistory findingId="f-1" />)
    expect(screen.getByTestId('section-load-error')).toHaveTextContent(
      'Could not load the import history'
    )
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(retry).toHaveBeenCalledTimes(1)
  })
})

describe('KEV in the finding header', () => {
  const base = { id: 'f1', title: 'Log4Shell', source: 'va', assets: [] }

  it('shows the KEV chip first when CISA lists the CVE', () => {
    render(
      <FindingHeader
        finding={{ ...base, isInKev: true, kevRansomware: true } as unknown as FindingDetail}
        status="new"
      />
    )
    const chips = document.querySelector('[data-slot="finding-header"] > div')
    expect(chips?.firstElementChild).toHaveAttribute('data-slot', 'exploit-signals')
    expect(screen.getByText('KEV')).toBeInTheDocument()
    expect(screen.getByText('Ransomware')).toBeInTheDocument()
  })

  it('shows no KEV chip otherwise', () => {
    render(<FindingHeader finding={base as unknown as FindingDetail} status="new" />)
    expect(document.querySelector('[data-slot="exploit-signals"]')).toBeNull()
  })
})
