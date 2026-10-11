import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const perms = vi.hoisted(() => ({ granted: new Set<string>() }))
const api = vi.hoisted(() => ({
  policy: { bearer_keys_allowed: false, key_bind_requires_approval: false } as {
    bearer_keys_allowed: boolean
    key_bind_requires_approval?: boolean
  },
  set: vi.fn(),
  mutate: vi.fn(async () => undefined),
}))

vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({ t: (k: string) => k }),
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

import { SensorKeyBindPolicySwitch } from '../sensor-key-bind-policy-switch'

describe('SensorKeyBindPolicySwitch', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.policy = { bearer_keys_allowed: false, key_bind_requires_approval: false }
  })

  it('renders nothing without sensors:read', () => {
    perms.granted = new Set()
    const { container } = render(<SensorKeyBindPolicySwitch />)
    expect(container).toBeEmptyDOMElement()
  })

  it('requiring approval needs sensors:grant:narrow and sends only that field', async () => {
    perms.granted = new Set(['sensors:read', 'sensors:grant:narrow'])
    api.set.mockResolvedValue({ bearer_keys_allowed: false, key_bind_requires_approval: true })
    const user = userEvent.setup()
    render(<SensorKeyBindPolicySwitch />)
    const sw = screen.getByRole('switch', { name: 'sensors.keyBindPolicy.label' })
    expect(sw).not.toBeChecked()
    await user.click(sw)
    await waitFor(() => expect(api.set).toHaveBeenCalledWith({ key_bind_requires_approval: true }))
  })

  it('allowing self-binding again is disabled without sensors:grant:widen', () => {
    perms.granted = new Set(['sensors:read', 'sensors:grant:narrow'])
    api.policy = { bearer_keys_allowed: false, key_bind_requires_approval: true }
    render(<SensorKeyBindPolicySwitch />)
    const sw = screen.getByRole('switch', { name: 'sensors.keyBindPolicy.label' })
    expect(sw).toBeChecked()
    expect(sw).toBeDisabled()
  })

  it('an older API without the field shows self-binding allowed', () => {
    perms.granted = new Set(['sensors:read'])
    api.policy = { bearer_keys_allowed: true }
    render(<SensorKeyBindPolicySwitch />)
    const sw = screen.getByRole('switch', { name: 'sensors.keyBindPolicy.label' })
    expect(sw).not.toBeChecked()
    expect(sw).toBeDisabled()
  })
})
