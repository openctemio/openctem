import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const postMock = vi.hoisted(() => vi.fn())
vi.mock('@/lib/api/client', () => ({ post: (...a: unknown[]) => postMock(...a) }))
vi.mock('@/lib/permissions', () => ({ usePermissions: () => ({ isAdmin: () => true }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { ScanOwnerBanner } from '../scan-owner-banner'

const config = {
  id: 's1',
  name: 'Nightly recon',
  owner_state: 'missing' as const,
  schedule_type: 'daily' as const,
  status: 'paused' as const,
}

describe('ScanOwnerBanner', () => {
  beforeEach(() => postMock.mockReset().mockResolvedValue({}))

  it('asks before taking ownership: scheduled runs will act as you', async () => {
    const user = userEvent.setup()
    render(<ScanOwnerBanner config={config} />)
    await user.click(screen.getByRole('button', { name: 'Take ownership' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Take ownership of "Nightly recon"?')
    expect(postMock).not.toHaveBeenCalled()
    await user.click(within(dialog).getByRole('button', { name: 'Take ownership' }))
    await waitFor(() =>
      expect(postMock).toHaveBeenCalledWith('/api/v1/scans/s1/take-ownership', {})
    )
  })

  it('Cancel takes nothing', async () => {
    const user = userEvent.setup()
    render(<ScanOwnerBanner config={config} />)
    await user.click(screen.getByRole('button', { name: 'Take ownership' }))
    await user.click(await screen.findByRole('button', { name: 'Cancel' }))
    expect(postMock).not.toHaveBeenCalled()
  })
})
