import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { CycleProfilesTab } from './cycle-detail-tabs'

const mutate = vi.fn(async () => undefined)
vi.mock('../api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../api')>()),
  useCycleProfiles: () => ({
    data: { data: [{ id: 'p1', name: 'Insider', profile_type: 'malicious_insider' }] },
    error: undefined,
    isLoading: false,
    mutate,
  }),
  useAttackerProfiles: () => ({
    data: {
      data: [
        { id: 'p1', name: 'Insider', profile_type: 'malicious_insider' },
        { id: 'p2', name: 'Outsider', profile_type: 'external_unauth' },
      ],
    },
  }),
  syncCycleProfiles: vi.fn(async () => {
    throw new Error('link failed midway')
  }),
}))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('cycle profiles save', () => {
  it('refreshes the list even when the save fails midway', async () => {
    const user = userEvent.setup()
    render(<CycleProfilesTab cycle={{ id: 'c1', status: 'planning' } as never} />)
    await user.click(screen.getByRole('button', { name: /choose profiles/i }))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(mutate).toHaveBeenCalled())
  })
})
