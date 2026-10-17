/**
 * ApprovalDialog Tests
 *
 * Tests for the finding status approval dialog component:
 * - Renders when open
 * - Shows justification textarea
 * - Submit button disabled when justification empty
 * - Calls onOpenChange when closed
 * - Shows target status label
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ApprovalDialog } from '../approval-dialog'

// ============================================
// MOCKS
// ============================================

// Mock the approval API hook
const mockRequestApproval = vi.fn()
// The false-positive policy of the finding (GET .../approvals/policy).
let mockPolicy: Record<string, unknown> | undefined
vi.mock('../../api/use-findings-api', () => ({
  useRequestApproval: vi.fn(() => ({
    trigger: mockRequestApproval,
    isMutating: false,
  })),
  useFindingApprovalPolicy: vi.fn(() => ({ data: mockPolicy })),
}))

// Mock the findings types
vi.mock('../../types', () => ({
  FINDING_STATUS_CONFIG: {
    new: { label: 'New', color: '', bgColor: '', textColor: '', icon: '', category: 'open' },
    confirmed: {
      label: 'Confirmed',
      color: '',
      bgColor: '',
      textColor: '',
      icon: '',
      category: 'open',
    },
    in_progress: {
      label: 'In Progress',
      color: '',
      bgColor: '',
      textColor: '',
      icon: '',
      category: 'in_progress',
    },
    resolved: {
      label: 'Resolved',
      color: '',
      bgColor: '',
      textColor: '',
      icon: '',
      category: 'closed',
    },
    false_positive: {
      label: 'False Positive',
      color: '',
      bgColor: '',
      textColor: '',
      icon: '',
      category: 'closed',
    },
    accepted: {
      label: 'Accepted',
      color: '',
      bgColor: '',
      textColor: '',
      icon: '',
      category: 'closed',
    },
    duplicate: {
      label: 'Duplicate',
      color: '',
      bgColor: '',
      textColor: '',
      icon: '',
      category: 'closed',
    },
    reopened: {
      label: 'Reopened',
      color: '',
      bgColor: '',
      textColor: '',
      icon: '',
      category: 'open',
    },
  },
}))

// Mock sonner toast
vi.mock('sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}))

// Mock error handler
vi.mock('@/lib/api/error-handler', () => ({
  getErrorMessage: vi.fn((error, fallback) => fallback || 'Error'),
}))

// ============================================
// SETUP
// ============================================

// The Reason select scrolls its options into view; jsdom has no layout.
if (!Element.prototype.scrollIntoView) Element.prototype.scrollIntoView = () => {}

/** Picks a closure reason in the Reason select. */
async function chooseReason(user: ReturnType<typeof userEvent.setup>, label: string) {
  await user.click(screen.getByRole('combobox'))
  await user.click(await screen.findByRole('option', { name: label }))
}

const defaultProps = {
  findingId: 'finding-123',
  targetStatus: 'false_positive' as const,
  open: true,
  onOpenChange: vi.fn(),
}

describe('ApprovalDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPolicy = undefined
  })

  // ============================================
  // ORGANIZATION'S FALSE-POSITIVE LEVEL
  // ============================================

  describe('false-positive level', () => {
    it('says no approval is needed and changes the submit when the caller may decide alone', async () => {
      mockPolicy = {
        fp_approval: 'off',
        single_person: true,
        can_decide_alone: true,
        material: false,
      }
      mockRequestApproval.mockResolvedValue({ status: 'approved', single_person: true })
      const user = userEvent.setup()
      render(<ApprovalDialog {...defaultProps} />)
      expect(screen.getByRole('status')).toHaveTextContent(
        /doesn't require approval for this finding/
      )
      await chooseReason(user, 'Test or example code')
      await user.type(screen.getByLabelText('Justification'), 'fixture')
      await user.click(screen.getByText('Review'))
      await user.click(screen.getByRole('button', { name: 'Mark as false positive' }))
      expect(mockRequestApproval).toHaveBeenCalledWith(
        expect.objectContaining({
          requested_status: 'false_positive',
          closure_reason: 'test_or_example_code',
        })
      )
    })

    it('says a person with approval permission could decide it alone', () => {
      mockPolicy = {
        fp_approval: 'off',
        single_person: true,
        can_decide_alone: false,
        material: false,
      }
      render(<ApprovalDialog {...defaultProps} />)
      expect(screen.queryByRole('status')).not.toBeInTheDocument()
      expect(screen.getByText(/could mark this finding a false positive alone/)).toBeInTheDocument()
    })

    it('keeps the four-eyes text when a second person is needed', () => {
      mockPolicy = {
        fp_approval: 'all',
        single_person: false,
        can_decide_alone: false,
        material: false,
      }
      render(<ApprovalDialog {...defaultProps} />)
      expect(screen.queryByRole('status')).not.toBeInTheDocument()
      expect(screen.queryByText(/alone/)).not.toBeInTheDocument()
    })
  })

  // ============================================
  // RENDERING
  // ============================================

  describe('rendering', () => {
    it('renders dialog when open is true', () => {
      render(<ApprovalDialog {...defaultProps} />)

      expect(screen.getByText('Request Status Approval')).toBeInTheDocument()
    })

    it('does not render dialog content when open is false', () => {
      render(<ApprovalDialog {...defaultProps} open={false} />)

      expect(screen.queryByText('Request Status Approval')).not.toBeInTheDocument()
    })

    it('shows the target status label in the description', () => {
      render(<ApprovalDialog {...defaultProps} targetStatus="false_positive" />)

      expect(screen.getByText('False Positive')).toBeInTheDocument()
    })

    it('shows justification textarea', () => {
      render(<ApprovalDialog {...defaultProps} />)

      expect(screen.getByLabelText('Justification')).toBeInTheDocument()
    })

    it('shows character count', () => {
      render(<ApprovalDialog {...defaultProps} />)

      expect(screen.getByText('0/2000 characters')).toBeInTheDocument()
    })

    it('shows review and cancel buttons', () => {
      render(<ApprovalDialog {...defaultProps} />)

      expect(screen.getByText('Review')).toBeInTheDocument()
      expect(screen.getByText('Cancel')).toBeInTheDocument()
    })
  })

  // ============================================
  // SUBMIT BUTTON STATE
  // ============================================

  describe('submit button state', () => {
    it('review button is disabled when justification is empty', () => {
      render(<ApprovalDialog {...defaultProps} />)

      const reviewButton = screen.getByText('Review')
      expect(reviewButton).toBeDisabled()
    })

    it('review button is disabled when justification is only whitespace', async () => {
      const user = userEvent.setup()
      render(<ApprovalDialog {...defaultProps} />)

      const textarea = screen.getByLabelText('Justification')
      await user.type(textarea, '   ')

      const reviewButton = screen.getByText('Review')
      expect(reviewButton).toBeDisabled()
    })

    it('review button stays disabled until a reason is chosen', async () => {
      const user = userEvent.setup()
      render(<ApprovalDialog {...defaultProps} />)

      await user.type(screen.getByLabelText('Justification'), 'This is a valid justification')
      expect(screen.getByText('Review')).toBeDisabled()

      await chooseReason(user, 'Scanner was wrong')
      expect(screen.getByText('Review')).toBeEnabled()
    })

    it('offers only the reasons of the requested status', async () => {
      const user = userEvent.setup()
      render(<ApprovalDialog {...defaultProps} targetStatus="accepted" />)
      await user.click(screen.getByRole('combobox'))
      expect(
        await screen.findByRole('option', { name: 'Compensating control' })
      ).toBeInTheDocument()
      expect(screen.queryByRole('option', { name: 'Scanner was wrong' })).not.toBeInTheDocument()
    })
  })

  // ============================================
  // INTERACTIONS
  // ============================================

  describe('interactions', () => {
    it('calls onOpenChange when cancel button is clicked', async () => {
      const user = userEvent.setup()
      const onOpenChange = vi.fn()
      render(<ApprovalDialog {...defaultProps} onOpenChange={onOpenChange} />)

      const cancelButton = screen.getByText('Cancel')
      await user.click(cancelButton)

      expect(onOpenChange).toHaveBeenCalledWith(false)
    })

    it('updates character count as user types', async () => {
      const user = userEvent.setup()
      render(<ApprovalDialog {...defaultProps} />)

      const textarea = screen.getByLabelText('Justification')
      await user.type(textarea, 'Hello')

      expect(screen.getByText('5/2000 characters')).toBeInTheDocument()
    })

    it('calls requestApproval on submit with valid justification', async () => {
      mockRequestApproval.mockResolvedValueOnce({})
      const user = userEvent.setup()
      render(<ApprovalDialog {...defaultProps} />)

      const textarea = screen.getByLabelText('Justification')
      await user.type(textarea, 'This is a justified reason')
      await chooseReason(user, 'Test or example code')

      // Step 1: Click Review to go to confirmation step
      const reviewButton = screen.getByText('Review')
      await user.click(reviewButton)

      // Step 2: Click Submit for Approval on confirmation step
      const submitButton = screen.getByText('Submit for Approval')
      await user.click(submitButton)

      expect(mockRequestApproval).toHaveBeenCalledWith({
        requested_status: 'false_positive',
        justification: 'This is a justified reason',
        closure_reason: 'test_or_example_code',
      })
    })

    it('an accepted risk always carries an expiry, 90 days ahead by default', async () => {
      mockRequestApproval.mockResolvedValueOnce({})
      const user = userEvent.setup()
      render(<ApprovalDialog {...defaultProps} targetStatus="accepted" />)

      const expiry = screen.getByLabelText('Acceptance expires on') as HTMLInputElement
      expect(expiry.required).toBe(true)
      expect(expiry.max).not.toBe('')

      await user.type(screen.getByLabelText('Justification'), 'Compensating control')
      await chooseReason(user, 'Compensating control')
      await user.click(screen.getByText('Review'))
      await user.click(screen.getByText('Submit for Approval'))

      const body = mockRequestApproval.mock.calls[0][0]
      expect(body.requested_status).toBe('accepted')
      expect(body.closure_reason).toBe('compensating_control')
      const days = (new Date(body.expires_at).getTime() - Date.now()) / 86_400_000
      expect(days).toBeGreaterThan(88)
      expect(days).toBeLessThan(91)
    })
  })

  // ============================================
  // STATUS LABELS
  // ============================================

  describe('status labels', () => {
    it('shows Resolved label for resolved status', () => {
      render(<ApprovalDialog {...defaultProps} targetStatus="resolved" />)

      expect(screen.getByText('Resolved')).toBeInTheDocument()
    })

    it('shows Accepted label for accepted status', () => {
      render(<ApprovalDialog {...defaultProps} targetStatus="accepted" />)

      expect(screen.getByText('Accepted')).toBeInTheDocument()
    })
  })
})

describe('ApprovalDialog acceptance cap', () => {
  it('a P0 or KEV finding defaults to and stops at its 30-day cap', () => {
    render(<ApprovalDialog {...defaultProps} targetStatus="accepted" maxAcceptanceDays={30} />)
    const expiry = screen.getByLabelText('Acceptance expires on') as HTMLInputElement
    const days = (Date.parse(`${expiry.max}T00:00:00`) - Date.now()) / 86_400_000
    expect(days).toBeGreaterThan(28)
    expect(days).toBeLessThan(31)
    const dflt = (Date.parse(`${expiry.value}T00:00:00`) - Date.now()) / 86_400_000
    expect(dflt).toBeLessThan(31)
  })
})

describe('ApprovalDialog approval policy', () => {
  const evaluation = {
    kind: 'accepted',
    tier: 'dual',
    floor: 'security',
    risk_class: 'critical',
    approvals_required: 2,
    reasons: ['severity_critical', 'kev', 'platform_default'],
    security_pool: true,
    security_pool_fallback: false,
    step_up: true,
    eligible_approvers: 5,
    eligible_security_pool: 2,
    satisfiable: true,
    min_note_length: 20,
    max_acceptance_days: 30,
    decide_within_days: 7,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    mockPolicy = undefined
  })

  it('explains the tier, the reasons and who approves', () => {
    mockPolicy = { evaluation }
    render(<ApprovalDialog {...defaultProps} targetStatus="accepted" />)
    const banner = screen.getByTestId('approval-evaluation')
    expect(banner).toHaveTextContent('Two approvers: 2 approval(s) needed')
    expect(banner).toHaveTextContent('Why: critical severity, known exploited (KEV).')
    expect(banner).toHaveTextContent('Set by the platform default.')
    expect(banner).toHaveTextContent('5 approvers, 2 in the security pool')
    expect(banner).toHaveTextContent('Approvers confirm their identity before they decide.')
    expect(banner).toHaveTextContent('at most 30 days')
    expect(screen.queryByTestId('approval-evaluation-unsatisfiable')).not.toBeInTheDocument()
  })

  it('limits the end date to the policy cap', () => {
    mockPolicy = { evaluation }
    render(<ApprovalDialog {...defaultProps} targetStatus="accepted" maxAcceptanceDays={365} />)
    const expiry = screen.getByLabelText('Acceptance expires on') as HTMLInputElement
    const days = (Date.parse(`${expiry.max}T00:00:00`) - Date.now()) / 86_400_000
    expect(days).toBeLessThan(31)
  })

  it('enforces the minimum note length', async () => {
    const user = userEvent.setup()
    mockPolicy = { evaluation: { ...evaluation, kind: 'false_positive', max_acceptance_days: 0 } }
    render(<ApprovalDialog {...defaultProps} />)
    await chooseReason(user, 'Test or example code')
    await user.click(screen.getByLabelText('Justification'))
    await user.paste('too short')
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Write at least 20 characters for this approval.'
    )
    expect(screen.getByRole('button', { name: 'Review' })).toBeDisabled()
    await user.paste(' but now long enough')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Review' })).toBeEnabled()
  })

  it('warns when the organization lacks eligible approvers', () => {
    mockPolicy = {
      evaluation: { ...evaluation, satisfiable: false, reasons: ['not_enough_eligible_approvers'] },
    }
    render(<ApprovalDialog {...defaultProps} targetStatus="accepted" />)
    expect(screen.getByTestId('approval-evaluation-unsatisfiable')).toHaveTextContent(
      'does not have enough eligible approvers'
    )
  })
})
