import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const api = vi.hoisted(() => ({
  data: { require_approval: true } as { require_approval: boolean; approval_off_at?: string },
  put: vi.fn(),
  mutate: vi.fn(async () => undefined),
}))
vi.mock('../api', () => ({
  useContentSettings: () => ({ data: api.data, error: undefined, mutate: api.mutate }),
  putContentSettings: api.put,
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { ApprovalSettings } from '../components/approval-settings'

describe('ApprovalSettings', () => {
  beforeEach(() => {
    api.put.mockReset().mockResolvedValue({ require_approval: true, approval_off_at: 'x' })
    api.data = { require_approval: true }
  })

  it('switching approval off asks first and says it takes effect in 24 hours', async () => {
    const user = userEvent.setup()
    render(<ApprovalSettings />)
    await user.click(screen.getByRole('switch', { name: /Require approval/ }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Switch approval off?')
    expect(dialog).toHaveTextContent('In 24 hours')
    expect(api.put).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Switch approval off' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith(false))
  })

  it('switching approval on is one click', async () => {
    api.data = { require_approval: false }
    const user = userEvent.setup()
    render(<ApprovalSettings />)
    await user.click(screen.getByRole('switch', { name: /Require approval/ }))
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    await waitFor(() => expect(api.put).toHaveBeenCalledWith(true))
  })
})
