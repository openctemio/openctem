/**
 * Small fixes on the finding page: copy-link failure, assignee permission,
 * locale dates, EPSS floor, scan id link.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { I18nProvider } from '@/context/i18n-provider'
import type { FindingDetail } from '../../../types'

const copy = vi.fn()
const toastSuccess = vi.fn()
const toastError = vi.fn()
let canMutate = true
let perms = new Set<string>()

vi.mock('@/lib/clipboard', () => ({ copyToClipboard: (...a: unknown[]) => copy(...a) }))
vi.mock('sonner', () => ({
  toast: {
    success: (...a: unknown[]) => toastSuccess(...a),
    error: (...a: unknown[]) => toastError(...a),
  },
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
  usePathname: () => '/',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useCanMutate: () => canMutate,
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => perms.has(p) }),
  usePermissionsSafe: () => ({ hasPermission: (p: string) => perms.has(p) }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't' } }),
  useCurrentTenantId: () => 't',
}))
vi.mock('@/features/ai-triage/components', () => ({ AITriageButton: () => null }))
vi.mock('@/features/ai-triage/api', () => ({ useTriageResult: () => ({ data: null }) }))
vi.mock('../../create-ticket-dialog', () => ({ CreateTicketDialog: () => null }))
vi.mock('../../mark-duplicate-dialog', () => ({ MarkDuplicateDialog: () => null }))
vi.mock('../../../hooks/use-can-create-ticket', () => ({ useCanCreateTicket: () => false }))
vi.mock('../../assignee-select', () => ({
  AssigneeSelect: ({ disabled }: { disabled?: boolean }) => (
    <button data-testid="assignee" disabled={disabled} />
  ),
}))
vi.mock('../../status-select', () => ({ StatusSelect: () => null }))
vi.mock('../../severity-select', () => ({ SeveritySelect: () => null }))
vi.mock('../finding-ticket-links', () => ({ FindingTicketLinks: () => null }))
vi.mock('../finding-people', () => ({
  FindingPeople: ({ assignee }: { assignee: React.ReactNode }) => <div>{assignee}</div>,
}))
vi.mock('../severity-provenance', () => ({ SeverityProvenance: () => null }))
vi.mock('../../../api/use-finding-identity', () => ({
  useFindingIdentity: () => ({
    identity: null,
    isLoading: false,
    error: undefined,
    mutate: vi.fn(),
  }),
}))
vi.mock('../../../api/use-finding-groups', () => ({ useRelatedCVEs: () => ({ data: undefined }) }))

const { FindingHeader } = await import('../finding-header')
const { FindingProperties } = await import('../finding-properties')
const { OverviewTab } = await import('../overview-tab')
const { SourceDataSection, formatScoreValue } = await import('../source-data-section')

function finding(over: Partial<FindingDetail> = {}): FindingDetail {
  return {
    id: 'f1',
    title: 'Heartbleed',
    description: 'd',
    severity: 'high',
    status: 'new',
    source: 'va',
    assets: [],
    evidence: [],
    remediation: { description: '', steps: [], references: [], progress: 0 },
    relatedFindings: [],
    discoveredAt: '2026-05-07T00:00:00Z',
    createdAt: '2026-05-07T00:00:00Z',
    updatedAt: '2026-05-07T00:00:00Z',
    activities: [],
    ...over,
  } as FindingDetail
}

beforeEach(() => {
  vi.clearAllMocks()
  canMutate = true
  perms = new Set()
})

describe('copy link', () => {
  async function clickCopy() {
    render(<FindingHeader finding={finding()} status="new" />)
    await userEvent.click(screen.getByRole('button', { name: 'More actions' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: /copy link/i }))
  }

  it('says so when copying fails, instead of "Link copied"', async () => {
    copy.mockResolvedValue(false)
    await clickCopy()
    expect(toastError).toHaveBeenCalledTimes(1)
    expect(toastSuccess).not.toHaveBeenCalled()
  })

  it('confirms when copying works', async () => {
    copy.mockResolvedValue(true)
    await clickCopy()
    expect(toastSuccess).toHaveBeenCalledTimes(1)
    expect(toastError).not.toHaveBeenCalled()
  })

  it('tells assistive tech that CVE and CWE links open a new tab', () => {
    render(<FindingHeader finding={finding({ cve: 'CVE-2024-1', cwe: 'CWE-79' })} status="new" />)
    expect(screen.getByRole('link', { name: /CVE-2024-1 on NVD.*new tab/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /CWE-79 on MITRE.*new tab/i })).toBeInTheDocument()
  })
})

describe('assignee picker', () => {
  const triage = { status: 'new', severity: 'high', assignee: null } as never

  it('is disabled without the assign permission', () => {
    canMutate = false
    render(<FindingProperties finding={finding()} triage={triage} />)
    expect(screen.getByTestId('assignee')).toBeDisabled()
  })

  it('is enabled with it', () => {
    render(<FindingProperties finding={finding()} triage={triage} />)
    expect(screen.getByTestId('assignee')).toBeEnabled()
  })
})

describe('locale dates', () => {
  const data = {
    scores: [],
    vulnerabilityIds: [],
    sourceExtra: [],
    lifecycle: { firstFound: '2024-07-03T10:00:00Z' },
  } as never

  it('uses Vietnamese month names under the vi locale', () => {
    const { container } = render(
      <I18nProvider locale="vi">
        <SourceDataSection data={data} />
      </I18nProvider>
    )
    expect(container.textContent).toMatch(/thg/i)
    expect(container.textContent).not.toMatch(/Jul/)
  })

  it('keeps English under en', () => {
    const { container } = render(
      <I18nProvider locale="en">
        <SourceDataSection data={data} />
      </I18nProvider>
    )
    expect(container.textContent).toMatch(/Jul/)
  })
})

describe('EPSS floor', () => {
  it('shows <0.01% for a tiny score, not 0.00%', () => {
    expect(formatScoreValue({ system: 'epss', value: 0.00004 })).toBe('<0.01%')
  })
  it('keeps normal scores', () => {
    expect(formatScoreValue({ system: 'epss', value: 0.0421 })).toBe('4.21%')
    expect(formatScoreValue({ system: 'epss', value: 0.5 })).toBe('50.0%')
  })
})

describe('scan id', () => {
  const f = () => finding({ scanId: 'run-123' })

  it('links to the run with scans:read', () => {
    perms = new Set(['scans:read'])
    render(<OverviewTab finding={f()} />)
    const a = screen.getByRole('link', { name: 'run-123' })
    expect(a.getAttribute('href')).toContain('run-123')
  })

  it('is plain text without it', () => {
    render(<OverviewTab finding={f()} />)
    expect(screen.getByText('run-123')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'run-123' })).toBeNull()
  })
})
