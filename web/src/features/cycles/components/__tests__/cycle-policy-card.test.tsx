import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

import { CyclePolicyCard } from '../cycle-policy-card'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

const perms = vi.hoisted(() => ({ admin: true }))
vi.mock('@/lib/permissions', () => ({
  Permission: { TeamUpdate: 'team:update' },
  usePermissions: () => ({ can: () => perms.admin }),
}))

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

beforeEach(() => {
  api.get.mockReset()
  api.put.mockReset()
  toast.success.mockReset()
  toast.error.mockReset()
  perms.admin = true
})

describe('CyclePolicyCard', () => {
  it('shows the policy to an admin and saves a change', async () => {
    api.get.mockResolvedValue({ enforce_coverage_slo: false })
    api.put.mockResolvedValue({ enforce_coverage_slo: true })
    wrap(<CyclePolicyCard />)

    const toggle = await screen.findByRole('switch')
    expect(toggle).toHaveAttribute('aria-checked', 'false')
    expect(api.get).toHaveBeenCalledWith('/api/v1/organization/settings/cycles')

    await userEvent.click(toggle)
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/v1/organization/settings/cycles', {
        enforce_coverage_slo: true,
      })
    )
    await waitFor(() => expect(toast.success).toHaveBeenCalled())
    expect(screen.getByRole('switch')).toHaveAttribute('aria-checked', 'true')
  })

  it('renders nothing and reads nothing for a member', async () => {
    perms.admin = false
    const { container } = wrap(<CyclePolicyCard />)
    await new Promise((r) => setTimeout(r, 0))
    expect(api.get).not.toHaveBeenCalled()
    expect(container).toBeEmptyDOMElement()
  })

  it('keeps the old value and reports the error when the save fails', async () => {
    api.get.mockResolvedValue({ enforce_coverage_slo: false })
    api.put.mockRejectedValue(new Error('forbidden'))
    wrap(<CyclePolicyCard />)
    await userEvent.click(await screen.findByRole('switch'))
    await waitFor(() => expect(toast.error).toHaveBeenCalled())
    expect(screen.getByRole('switch')).toHaveAttribute('aria-checked', 'false')
  })
})
