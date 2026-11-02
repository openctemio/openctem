import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { APIKeyPolicyCard } from '../api-key-policy-card'

const policy = { max_lifetime_days: 90, default_max_lifetime_days: 90, ceiling_days: 365 }
const update = vi.fn()
const mutate = vi.fn()

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/features/api-keys/api/use-api-keys', () => ({
  useApiKeyPolicy: () => ({ data: policy, mutate }),
  updateApiKeyPolicy: (...a: unknown[]) => update(...a),
}))

async function setDays(v: string) {
  const input = screen.getByLabelText(/Days \(1 to 365\)/)
  await userEvent.clear(input)
  await userEvent.type(input, v)
}

describe('APIKeyPolicyCard', () => {
  beforeEach(() => vi.clearAllMocks())

  it('saves a shorter maximum at once', async () => {
    update.mockResolvedValue({ ...policy, max_lifetime_days: 30 })
    render(<APIKeyPolicyCard canEdit />)
    await setDays('30')
    await userEvent.click(screen.getByRole('button', { name: /^Save/ }))
    await waitFor(() => expect(update).toHaveBeenCalledWith(30))
    expect(screen.queryByText('Allow longer-lived keys?')).not.toBeInTheDocument()
  })

  it('asks before a longer maximum', async () => {
    update.mockResolvedValue({ ...policy, max_lifetime_days: 180 })
    render(<APIKeyPolicyCard canEdit />)
    await setDays('180')
    await userEvent.click(screen.getByRole('button', { name: /^Save/ }))
    expect(update).not.toHaveBeenCalled()
    expect(await screen.findByText('Allow longer-lived keys?')).toBeInTheDocument()
    await userEvent.click(screen.getAllByRole('button', { name: 'Save' }).at(-1)!)
    await waitFor(() => expect(update).toHaveBeenCalledWith(180))
  })

  it('refuses a value above the platform ceiling and is read only without the permission', async () => {
    const { unmount } = render(<APIKeyPolicyCard canEdit />)
    await setDays('400')
    await userEvent.click(screen.getByRole('button', { name: /^Save/ }))
    expect(update).not.toHaveBeenCalled()
    unmount()
    render(<APIKeyPolicyCard canEdit={false} />)
    expect(screen.getByLabelText(/Days \(1 to 365\)/)).toBeDisabled()
  })
})
