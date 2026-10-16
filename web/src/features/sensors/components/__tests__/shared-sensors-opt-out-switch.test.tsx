import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const role = vi.hoisted(() => ({ value: 'owner' as 'owner' | 'admin' | 'member' }))
const api = vi.hoisted(() => ({
  data: { opt_out: false } as { opt_out: boolean } | undefined,
  put: vi.fn(),
  mutate: vi.fn(async () => undefined),
}))

vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({ t: (k: string) => k }),
}))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({
    isOwner: () => role.value === 'owner',
    isAdmin: () => role.value === 'owner' || role.value === 'admin',
  }),
}))
vi.mock('swr', () => ({
  default: (key: string | null) => ({
    data: key ? api.data : undefined,
    mutate: api.mutate,
    isLoading: false,
  }),
}))
vi.mock('@/lib/api/client', () => ({ get: vi.fn(), put: api.put }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { SharedSensorsOptOutSwitch } from '../shared-sensors-opt-out-switch'

describe('SharedSensorsOptOutSwitch', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.data = { opt_out: false }
  })

  it('renders nothing for a member', () => {
    role.value = 'member'
    const { container } = render(<SharedSensorsOptOutSwitch />)
    expect(container).toBeEmptyDOMElement()
  })

  it('an administrator sees it but cannot change it', () => {
    role.value = 'admin'
    render(<SharedSensorsOptOutSwitch />)
    const sw = screen.getByRole('switch', { name: 'sensors.sharedOptOut.label' })
    expect(sw).toBeDisabled()
    expect(screen.getByText('sensors.sharedOptOut.ownerOnly')).toBeInTheDocument()
  })

  it('the owner opts out', async () => {
    role.value = 'owner'
    api.put.mockResolvedValue({ opt_out: true })
    const user = userEvent.setup()
    render(<SharedSensorsOptOutSwitch />)
    const sw = screen.getByRole('switch', { name: 'sensors.sharedOptOut.label' })
    expect(sw).not.toBeChecked()
    await user.click(sw)
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/v1/organization/settings/shared-sensors', {
        opt_out: true,
      })
    )
  })
})
