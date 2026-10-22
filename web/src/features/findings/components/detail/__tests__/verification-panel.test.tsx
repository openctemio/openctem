/**
 * VerificationPanel renders the server's verification plan: a secret offers
 * rotation proof and evidence review and says why a retest, a covered scan
 * and a reachability check cannot verify it; a network finding offers the
 * retest; the checklist editor saves through the API and needs the checklist
 * permission; the completer is told another person must resolve.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { VerificationPanel } from '../verification-panel'
import type { VerificationPlan } from '../../../api/use-finding-verification'

let mockPlan: VerificationPlan | undefined
let mockHasPermission = (_: string) => true
const mockSave = vi.fn()

vi.mock('../../../api/use-finding-verification', () => ({
  useFindingVerificationPlan: () => ({ data: mockPlan, error: undefined }),
  useVerificationChecklist: () => ({
    data: {
      id: 'c-1',
      finding_id: 'f-1',
      exposure_cleared: false,
      evidence_attached: false,
      register_updated: false,
      notes: '',
      is_complete: false,
    },
    isLoading: false,
  }),
  saveVerificationChecklist: (...args: unknown[]) => mockSave(...args),
  findingVerificationKey: (id: string) => `/api/v1/findings/${id}/verification`,
  verificationChecklistKey: (id: string) => `/api/v1/verification-checklists/${id}`,
}))

vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => mockHasPermission(p) }),
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const secretPlan = (over: Partial<VerificationPlan> = {}): VerificationPlan => ({
  finding_id: 'f-1',
  status: 'confirmed',
  tier: 'critical',
  requirement: 'second_person_or_retest',
  second_person_required: true,
  proof_present: false,
  methods: [
    { kind: 'rotation_proof', available: true, recommended: true, counts_as_proof: true },
    { kind: 'evidence_review', available: true, counts_as_proof: true },
    { kind: 'retest', available: false, counts_as_proof: true, reason: 'secret_needs_rotation' },
    {
      kind: 'covered_scan',
      available: false,
      counts_as_proof: true,
      automatic: true,
      reason: 'absence_not_proof_for_secrets',
    },
    { kind: 'safe_check', available: false, counts_as_proof: false, reason: 'not_for_secrets' },
  ],
  evidence: { checklist: { state: 'none', fresh: false } },
  ...over,
})

describe('VerificationPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockHasPermission = () => true
    mockPlan = secretPlan()
    mockSave.mockResolvedValue({ is_complete: true })
  })

  it('offers rotation proof for a secret and says why the rest cannot verify it', () => {
    render(<VerificationPanel findingId="f-1" />)
    expect(screen.getByText('Rotation proof')).toBeInTheDocument()
    expect(screen.getByText('Recommended')).toBeInTheDocument()
    expect(
      screen.getByText('A leaked secret is verified by rotating it, not by a re-check')
    ).toBeInTheDocument()
    expect(
      screen.getByText('A secret stays valid after it is removed from code')
    ).toBeInTheDocument()
    expect(screen.getByText('Reachability says nothing about a leaked secret')).toBeInTheDocument()
    expect(screen.getByText(/checklist completed by another person/)).toBeInTheDocument()
  })

  it('offers the retest for a network finding', () => {
    mockPlan = secretPlan({
      tier: 'high',
      requirement: 'checklist_or_retest',
      second_person_required: false,
      methods: [
        { kind: 'retest', available: true, recommended: true, counts_as_proof: true },
        { kind: 'evidence_review', available: true, counts_as_proof: true },
        { kind: 'safe_check', available: true, counts_as_proof: false },
      ],
    })
    render(<VerificationPanel findingId="f-1" />)
    expect(
      screen.getByText('Re-runs the check that found it against its target.')
    ).toBeInTheDocument()
    expect(screen.queryByText('Rotation proof')).not.toBeInTheDocument()
  })

  it('saves the checklist through the API', async () => {
    const user = userEvent.setup()
    render(<VerificationPanel findingId="f-1" />)
    await user.click(screen.getByRole('button', { name: /checklist/i }))
    for (const box of screen.getAllByRole('checkbox')) await user.click(box)
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(mockSave).toHaveBeenCalledWith(
      'f-1',
      expect.objectContaining({
        exposure_cleared: true,
        evidence_attached: true,
        register_updated: true,
      })
    )
  })

  it('hides the checklist editor without the checklist permission', () => {
    mockHasPermission = (p) => p !== 'ctem:verification_checklists:write'
    render(<VerificationPanel findingId="f-1" />)
    expect(screen.queryByRole('button', { name: /checklist/i })).not.toBeInTheDocument()
  })

  it('tells the completer that another person must resolve', () => {
    mockPlan = secretPlan({
      proof_present: true,
      evidence: {
        checklist: {
          state: 'complete',
          fresh: true,
          completed_by: 'u-1',
          completed_at: '2026-10-20T00:00:00Z',
          completed_by_caller: true,
        },
      },
    })
    render(<VerificationPanel findingId="f-1" />)
    expect(screen.getByText(/another person must resolve this finding/)).toBeInTheDocument()
  })

  it('renders nothing for a pentest finding or a closed one', () => {
    mockPlan = secretPlan({ external_workflow: 'pentest', methods: [] })
    const { container, rerender } = render(<VerificationPanel findingId="f-1" />)
    expect(container).toBeEmptyDOMElement()
    mockPlan = secretPlan({
      methods: [
        {
          kind: 'evidence_review',
          available: false,
          counts_as_proof: true,
          reason: 'finding_closed',
        },
      ],
    })
    rerender(<VerificationPanel findingId="f-1" />)
    expect(container).toBeEmptyDOMElement()
  })
})
