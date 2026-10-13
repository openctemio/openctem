/**
 * A scan without an active owner: the banner says why, offers "Take
 * ownership" to owners and administrators only, and posts to the scan's
 * take-ownership endpoint. Nothing shows for a scan with an active owner.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
const api = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('@/lib/api/client', () => ({ post: api.post }))
const role = vi.hoisted(() => ({ admin: false }))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ isAdmin: () => role.admin }),
}))

const { ScanOwnerBanner } = await import('../scan-owner-banner')

const base = { id: 'scan-1', name: 'Nightly', schedule_type: 'daily', status: 'paused' } as const

describe('ScanOwnerBanner', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    role.admin = false
  })

  it('renders nothing while the owner is active', () => {
    const { container } = render(<ScanOwnerBanner config={{ ...base, owner_state: 'ok' }} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('tells a member to ask an administrator, with no button', () => {
    render(<ScanOwnerBanner config={{ ...base, owner_state: 'missing' }} />)
    expect(screen.getByText(/no longer exists/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Take ownership' })).toBeNull()
    expect(screen.getByText(/administrator can take ownership/)).toBeInTheDocument()
  })

  it('lets an administrator take ownership in one click', async () => {
    role.admin = true
    api.post.mockResolvedValue({})
    const onChanged = vi.fn()
    render(<ScanOwnerBanner config={{ ...base, owner_state: 'inactive' }} onChanged={onChanged} />)
    expect(screen.getByText(/no longer an active member/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Take ownership' }))
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
    expect(api.post).toHaveBeenCalledWith('/api/v1/scans/scan-1/take-ownership', {})
    expect(toast.success).toHaveBeenCalled()
  })

  it('shows the refusal when the API refuses', async () => {
    role.admin = true
    api.post.mockRejectedValue(new Error("This scan's owner is an active member."))
    render(<ScanOwnerBanner config={{ ...base, owner_state: 'missing' }} />)
    await userEvent.click(screen.getByRole('button', { name: 'Take ownership' }))
    await waitFor(() => expect(toast.error).toHaveBeenCalled())
  })
})
