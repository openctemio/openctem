/**
 * Retest check section (research/221)
 * - nothing renders without a check and without findings:retest_checks:write
 * - a writer sees the empty state and opens the editor
 * - Save is enabled only after a valid validation of exactly this input
 * - an invalid validation shows the field errors and keeps Save disabled
 * - Approve shows only with scope approval rights, when approval is required and missing
 * - a 409 on approve explains that a second person must approve
 * - a retest that ran the check names it and its digest in the history
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingRetestCheckSection } from '../finding-retest-check'
import { RetestCheckProvenance } from '../finding-retest'
import type { RetestCheck, RetestCheckValidation } from '../../../api/use-finding-retest-check'
import { ApiClientError } from '@/lib/api/error-handler'

let mockCheck: RetestCheck | null = null
let mockPerms = new Set<string>()
const mockValidate = vi.fn()
const mockSave = vi.fn()
const mockRemove = vi.fn()
const mockApprove = vi.fn()
const mockToastError = vi.fn()

vi.mock('../../../api/use-finding-retest-check', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../api/use-finding-retest-check')>()
  return {
    ...real,
    useFindingRetestCheck: () => ({
      data: { check: mockCheck },
      error: undefined,
      isLoading: false,
    }),
    useValidateRetestCheck: () => ({ trigger: mockValidate, isMutating: false }),
    useSaveRetestCheck: () => ({ trigger: mockSave, isMutating: false }),
    useRemoveRetestCheck: () => ({ trigger: mockRemove, isMutating: false }),
    useApproveRetestCheck: () => ({ trigger: mockApprove, isMutating: false }),
  }
})

vi.mock('../../../api/use-finding-retests', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../api/use-finding-retests')>()
  return { ...real, useFindingRetests: () => ({ data: { data: [] } }) }
})

vi.mock('@/lib/api/scanner-template-hooks', () => ({
  useScannerTemplates: () => ({ data: { items: [] }, isLoading: false }),
}))

vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => mockPerms.has(p) }),
}))

vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: (...a: unknown[]) => mockToastError(...a) },
}))

const WRITE = 'findings:retest_checks:write'
const APPROVE = 'attack_surface:scope:approve'

function check(over: Partial<RetestCheck> = {}): RetestCheck {
  return {
    id: 'c-1',
    finding_id: 'f-1',
    kind: 'http_assertion',
    template_id: 'tpl-1',
    template_name: 'Reflected XSS on /search',
    template_digest: 'sha256:abcdef1234567890abcdef1234567890',
    content: 'id: x',
    assertion: {
      method: 'GET',
      path: '/search?q=x',
      matchers: [{ type: 'status', status: [200] }],
    },
    tier: 'T1',
    tier_reason: 'sends payloads',
    approval: { required: false, approved: false },
    template_pending_sensor_approval: false,
    calibrated: false,
    created_at: '2026-10-20T00:00:00Z',
    updated_at: '2026-10-20T00:00:00Z',
    ...over,
  }
}

function validation(over: Partial<RetestCheckValidation> = {}): RetestCheckValidation {
  return {
    valid: true,
    errors: [],
    tier: 'T0',
    tier_reason: 'passive request',
    capabilities: ['http'],
    content: 'id: generated\nhttp: []',
    approval_required: false,
    ...over,
  }
}

const finding = { id: 'f-1' }

describe('FindingRetestCheckSection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockCheck = null
    mockPerms = new Set()
    mockSave.mockResolvedValue(check())
  })

  it('renders nothing without a check and without the write permission', () => {
    const { container } = render(<FindingRetestCheckSection finding={finding} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the empty state with Add check to a writer', () => {
    mockPerms = new Set([WRITE])
    render(<FindingRetestCheckSection finding={finding} />)
    expect(screen.getByText(/No retest check/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add check' })).toBeInTheDocument()
  })

  it('saves an HTTP assertion only after a valid validation of the same input', async () => {
    mockPerms = new Set([WRITE])
    mockValidate.mockResolvedValue(validation())
    const user = userEvent.setup()
    render(<FindingRetestCheckSection finding={finding} />)
    await user.click(screen.getByRole('button', { name: 'Add check' }))

    const path = screen.getByLabelText('Path')
    await user.clear(path)
    await user.type(path, '/search')
    const save = screen.getByRole('button', { name: 'Save' })
    expect(save).toBeDisabled()

    await user.click(screen.getByRole('button', { name: 'Validate' }))
    await waitFor(() => expect(save).toBeEnabled())
    expect(mockValidate).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: 'http_assertion',
        assertion: expect.objectContaining({
          method: 'GET',
          path: '/search',
          matchers: [{ type: 'status', status: [200] }],
        }),
      })
    )
    expect(screen.getByText('T0 · passive')).toBeInTheDocument()

    // Changing the input after validating requires a new validation.
    await user.type(path, 'x')
    expect(save).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Validate' }))
    await waitFor(() => expect(save).toBeEnabled())

    await user.click(save)
    await waitFor(() => expect(mockSave).toHaveBeenCalledTimes(1))
    expect(mockSave.mock.calls[0][0].assertion.path).toBe('/searchx')
  }, 20_000)

  it('shows field errors of an invalid check and keeps Save disabled', async () => {
    mockPerms = new Set([WRITE])
    mockValidate.mockResolvedValue(
      validation({
        valid: false,
        errors: [{ field: 'assertion.path', message: 'path must start with /', code: 'invalid' }],
      })
    )
    const user = userEvent.setup()
    render(<FindingRetestCheckSection finding={finding} />)
    await user.click(screen.getByRole('button', { name: 'Add check' }))
    await user.click(screen.getByRole('button', { name: 'Validate' }))
    expect(await screen.findAllByText('path must start with /')).not.toHaveLength(0)
    expect(screen.getByText('The check has errors')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('warns about credential headers before sending', async () => {
    mockPerms = new Set([WRITE])
    const user = userEvent.setup()
    render(<FindingRetestCheckSection finding={finding} />)
    await user.click(screen.getByRole('button', { name: 'Add check' }))
    await user.click(screen.getByRole('button', { name: 'Add header' }))
    await user.type(screen.getByLabelText('Header name'), 'Authorization')
    expect(screen.getByText(/Credentials are not allowed in a check:/)).toBeInTheDocument()
  }, 20_000)

  it('shows the saved check with digest, tier and calibration to a reader', () => {
    mockCheck = check()
    render(<FindingRetestCheckSection finding={finding} />)
    expect(screen.getByText('Reflected XSS on /search')).toBeInTheDocument()
    expect(screen.getByText(/sha256:abcdef123456/)).toBeInTheDocument()
    expect(screen.getByText('T1 · active')).toBeInTheDocument()
    expect(screen.getByText('Not calibrated yet')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Edit check' })).not.toBeInTheDocument()
  })

  it('offers Approve only to a scope approver when approval is required and missing', () => {
    mockCheck = check({ tier: 'T2', approval: { required: true, approved: false } })
    const { rerender } = render(<FindingRetestCheckSection finding={finding} />)
    expect(screen.getByText('Awaiting approval')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()

    mockPerms = new Set([APPROVE])
    rerender(<FindingRetestCheckSection finding={finding} />)
    expect(screen.getByRole('button', { name: 'Approve' })).toBeInTheDocument()

    mockCheck = check({ tier: 'T2', approval: { required: true, approved: true } })
    rerender(<FindingRetestCheckSection finding={finding} />)
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()

    mockCheck = check({ tier: 'T1', approval: { required: false, approved: false } })
    rerender(<FindingRetestCheckSection finding={finding} />)
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
  })

  it('explains a 409 on approve (the approver wrote this version)', async () => {
    mockPerms = new Set([APPROVE])
    mockCheck = check({ tier: 'T2', approval: { required: true, approved: false } })
    mockApprove.mockRejectedValue(
      new ApiClientError('the author cannot approve their own check', 'CONFLICT', 409)
    )
    const user = userEvent.setup()
    render(<FindingRetestCheckSection finding={finding} />)
    await user.click(screen.getByRole('button', { name: 'Approve' }))
    await waitFor(() =>
      expect(mockToastError).toHaveBeenCalledWith(
        'You cannot approve this version of the check',
        expect.objectContaining({ description: 'the author cannot approve their own check' })
      )
    )
  })
})

describe('RetestCheckProvenance', () => {
  it('names the custom check and its short digest on a history entry', () => {
    render(
      <RetestCheckProvenance
        retest={{
          id: 'r-1',
          retest_check_id: 'c-1',
          check_digest: 'sha256:abcdef1234567890abcdef',
        }}
        check={check()}
      />
    )
    expect(
      screen.getByText(/Checked with custom check Reflected XSS on \/search/)
    ).toBeInTheDocument()
    expect(screen.getByText('(sha256:abcdef123456)')).toBeInTheDocument()
  })

  it('shows nothing for a retest that did not run a check', () => {
    const { container } = render(<RetestCheckProvenance retest={{ id: 'r-1' }} check={check()} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('omits the name of a replaced check', () => {
    render(
      <RetestCheckProvenance
        retest={{ id: 'r-1', retest_check_id: 'old', check_digest: 'sha256:1234567890abcdef' }}
        check={check()}
      />
    )
    expect(screen.getByText(/Checked with a custom check/)).toBeInTheDocument()
  })
})
