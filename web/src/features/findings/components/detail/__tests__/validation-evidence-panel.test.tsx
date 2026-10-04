/**
 * ValidationEvidencePanel Tests (RFC-011)
 * - empty state when no evidence
 * - renders evidence rows with outcome label
 * - "Validate now" triggers a validation request (findings:write)
 * - button hidden without findings:write
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
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

  it('triggers a validation request when "Validate now" is clicked', async () => {
    const user = userEvent.setup()
    render(<ValidationEvidencePanel findingId="f-1" />)
    await user.click(screen.getByRole('button', { name: /validate now/i }))
    expect(mockRequestValidation).toHaveBeenCalledTimes(1)
  })

  it('hides the action without findings:write permission', () => {
    mockHasPermission = () => false
    render(<ValidationEvidencePanel findingId="f-1" />)
    expect(screen.queryByRole('button', { name: /validate now/i })).not.toBeInTheDocument()
  })
})
