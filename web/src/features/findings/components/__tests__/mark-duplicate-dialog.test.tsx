/**
 * MarkDuplicateDialog: offers the other findings of the same asset (never the
 * finding itself or a duplicate), posts the picked one, and reports errors.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MarkDuplicateDialog } from '../mark-duplicate-dialog'

const mockTrigger = vi.fn()
const mockUseFindings = vi.fn()
vi.mock('../../api/use-findings-api', () => ({
  useFindingsApi: (...args: unknown[]) => mockUseFindings(...args),
  useMarkDuplicateApi: vi.fn(() => ({ trigger: mockTrigger, isMutating: false })),
}))
vi.mock('swr', () => ({ mutate: vi.fn() }))
const toastError = vi.fn()
vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: (...a: unknown[]) => toastError(...a) },
}))

const finding = (id: string, title: string, status = 'new') => ({
  id,
  title,
  status,
  tool_name: 'semgrep',
  message: title,
})

describe('MarkDuplicateDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseFindings.mockReturnValue({
      data: {
        data: [
          finding('self', 'This finding'),
          finding('orig', 'Original SQL injection', 'confirmed'),
          finding('tomb', 'Already folded', 'duplicate'),
        ],
      },
      isLoading: false,
    })
  })

  it('lists other findings on the same asset only', () => {
    render(<MarkDuplicateDialog findingId="self" assetId="asset-1" open onOpenChange={vi.fn()} />)
    expect(screen.getByText('Original SQL injection')).toBeInTheDocument()
    expect(screen.queryByText('This finding')).not.toBeInTheDocument()
    expect(screen.queryByText('Already folded')).not.toBeInTheDocument()
    const [filters, opts] = mockUseFindings.mock.calls[0]
    expect(filters).toMatchObject({ asset_id: 'asset-1', exclude_statuses: ['duplicate'] })
    expect(opts).toMatchObject({ enabled: true })
  })

  it('does not fetch while closed', () => {
    render(
      <MarkDuplicateDialog findingId="self" assetId="asset-1" open={false} onOpenChange={vi.fn()} />
    )
    expect(mockUseFindings.mock.calls[0][1]).toMatchObject({ enabled: false })
  })

  it('posts the picked finding and reports the canonical id', async () => {
    mockTrigger.mockResolvedValue({ id: 'orig' })
    const onMarked = vi.fn()
    const onOpenChange = vi.fn()
    render(
      <MarkDuplicateDialog
        findingId="self"
        assetId="asset-1"
        open
        onOpenChange={onOpenChange}
        onMarked={onMarked}
      />
    )
    const confirm = screen.getByRole('button', { name: 'Mark as duplicate' })
    expect(confirm).toBeDisabled()
    await userEvent.click(screen.getByText('Original SQL injection'))
    await userEvent.click(confirm)
    expect(mockTrigger).toHaveBeenCalledWith({ duplicate_of_id: 'orig' })
    expect(onMarked).toHaveBeenCalledWith('orig')
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('shows the API error and stays open', async () => {
    mockTrigger.mockRejectedValue(new Error('requires findings:approve'))
    const onMarked = vi.fn()
    render(
      <MarkDuplicateDialog
        findingId="self"
        assetId="asset-1"
        open
        onOpenChange={vi.fn()}
        onMarked={onMarked}
      />
    )
    await userEvent.click(screen.getByText('Original SQL injection'))
    await userEvent.click(screen.getByRole('button', { name: 'Mark as duplicate' }))
    expect(toastError).toHaveBeenCalled()
    expect(onMarked).not.toHaveBeenCalled()
  })
})
