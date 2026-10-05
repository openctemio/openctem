import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const perms = vi.hoisted(() => ({ granted: new Set<string>() }))
const api = vi.hoisted(() => ({
  policy: { bearer_keys_allowed: true },
  set: vi.fn(),
  mutate: vi.fn(async () => undefined),
}))

vi.mock('@/lib/permissions', () => ({
  Permission: {
    SensorsRead: 'sensors:read',
    SensorsGrantNarrow: 'sensors:grant:narrow',
    SensorsGrantWiden: 'sensors:grant:widen',
  },
  useHasPermission: (p: string) => perms.granted.has(p),
}))
vi.mock('@/lib/api/sensor-pairing-hooks', () => ({
  useSensorIdentityPolicy: () => ({ data: api.policy, mutate: api.mutate, isLoading: false }),
  setSensorIdentityPolicy: api.set,
}))

import { SensorIdentityPolicySwitch } from '../sensor-identity-policy-switch'

describe('SensorIdentityPolicySwitch', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.policy = { bearer_keys_allowed: true }
  })

  it('renders nothing without sensors:read', () => {
    perms.granted = new Set()
    const { container } = render(<SensorIdentityPolicySwitch />)
    expect(container).toBeEmptyDOMElement()
  })

  it('narrowing (require key-bound identity) needs sensors:grant:narrow', async () => {
    perms.granted = new Set(['sensors:read', 'sensors:grant:narrow'])
    api.set.mockResolvedValue({ bearer_keys_allowed: false })
    const user = userEvent.setup()
    render(<SensorIdentityPolicySwitch />)
    const sw = screen.getByRole('switch', { name: /require key-bound sensor identity/i })
    expect(sw).toBeEnabled()
    await user.click(sw)
    await waitFor(() => expect(api.set).toHaveBeenCalledWith({ bearer_keys_allowed: false }))
  })

  it('widening (allow bearer keys again) is disabled without sensors:grant:widen', () => {
    perms.granted = new Set(['sensors:read', 'sensors:grant:narrow'])
    api.policy = { bearer_keys_allowed: false }
    render(<SensorIdentityPolicySwitch />)
    const sw = screen.getByRole('switch', { name: /require key-bound sensor identity/i })
    expect(sw).toBeChecked()
    expect(sw).toBeDisabled()
  })

  it('a read-only viewer sees the policy but cannot change it', () => {
    perms.granted = new Set(['sensors:read'])
    render(<SensorIdentityPolicySwitch />)
    expect(
      screen.getByRole('switch', { name: /require key-bound sensor identity/i })
    ).toBeDisabled()
  })
})
