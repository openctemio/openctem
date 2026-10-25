/**
 * ValidationEvidencePanel Tests (RFC-011)
 * - empty state when no evidence
 * - renders evidence rows with outcome label
 * - "Check reachability" triggers a validation request (findings:verify),
 *   offered only where the verification plan says a safe-check can run
 * - nothing rendered when there is no evidence and no safe-check
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ValidationEvidencePanel } from '../validation-evidence-panel'

const mockRequestValidation = vi.fn()
const mockMutate = vi.fn()
let mockEvidence: unknown[] = []
let mockHasPermission = (_: string) => true

vi.mock('../../../api/use-findings-api', () => ({
  useRequestValidationApi: () => ({ trigger: mockRequestValidation, isMutating: false }),
  useFindingValidationEvidenceApi: () => ({
    data: { evidence: mockEvidence },
    isLoading: false,
    mutate: mockMutate,
  }),
}))

let mockSafeCheck: { kind: string; available: boolean; reason?: string } | undefined = {
  kind: 'safe_check',
  available: true,
}
vi.mock('../../../api/use-finding-verification', () => ({
  useFindingVerificationPlan: () => ({
    data: mockSafeCheck ? { methods: [mockSafeCheck] } : undefined,
  }),
  planMethod: (plan: { methods: { kind: string }[] } | undefined, kind: string) =>
    plan?.methods.find((m) => m.kind === kind),
}))

vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => mockHasPermission(p) }),
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('ValidationEvidencePanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockRequestValidation.mockResolvedValue({ command_id: 'cmd-1', status: 'queued' })
    mockEvidence = []
    mockHasPermission = () => true
    mockSafeCheck = { kind: 'safe_check', available: true }
  })

  it('shows the empty state when there is no evidence', () => {
    render(<ValidationEvidencePanel findingId="f-1" />)
    expect(screen.getByText(/No validation evidence yet/i)).toBeInTheDocument()
  })

  it('renders evidence rows with a human outcome label', () => {
    mockEvidence = [
      {
        id: 'e-1',
        finding_id: 'f-1',
        executor_kind: 'safe-check',
        technique: 'T1046',
        outcome: 'not_detected',
        summary: 'port closed',
        created_at: '2026-07-02T00:00:00Z',
      },
    ]
    render(<ValidationEvidencePanel findingId="f-1" />)
    // A safe-check is a reachability probe, never "the fix stood" (RFC-039 D3).
    expect(screen.getByText('Not reachable')).toBeInTheDocument()
    expect(screen.queryByText(/fix stood/i)).not.toBeInTheDocument()
    expect(screen.getByText('port closed')).toBeInTheDocument()
  })

  it('labels a template re-run by its detection outcome', () => {
    mockEvidence = [
      {
        id: 'e-2',
        finding_id: 'f-1',
        executor_kind: 'nuclei',
        technique: 'T1190',
        outcome: 'detected',
        summary: 'matched',
        created_at: '2026-07-02T00:00:00Z',
      },
    ]
    render(<ValidationEvidencePanel findingId="f-1" />)
    expect(screen.getByText(/Detected \(still exploitable\)/)).toBeInTheDocument()
  })

  it('triggers a validation request when "Check reachability" is clicked', async () => {
    const user = userEvent.setup()
    render(<ValidationEvidencePanel findingId="f-1" />)
    await user.click(screen.getByRole('button', { name: /check reachability/i }))
    expect(mockRequestValidation).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    await user.click(within(dialog).getByRole('button', { name: 'Run safe check' }))
    expect(mockRequestValidation).toHaveBeenCalledTimes(1)
  })

  it('needs findings:verify for the check', () => {
    mockHasPermission = (p) => p !== 'findings:verify'
    render(<ValidationEvidencePanel findingId="f-1" />)
    expect(screen.queryByRole('button', { name: /check reachability/i })).not.toBeInTheDocument()
  })

  it('offers no check where the plan says it cannot run, and shows nothing without evidence', () => {
    mockSafeCheck = { kind: 'safe_check', available: false, reason: 'not_for_secrets' }
    const { container } = render(<ValidationEvidencePanel findingId="f-1" />)
    expect(screen.queryByRole('button', { name: /check reachability/i })).not.toBeInTheDocument()
    expect(container).toBeEmptyDOMElement()
  })
})
