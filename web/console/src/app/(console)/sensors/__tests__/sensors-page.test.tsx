import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { actOnSharedSensor } from '@console/features/admin-console/api/use-shared-fleet'
import PlatformSensorsPage from '../page'

const state = vi.hoisted(() => ({
  role: 'readonly' as string,
  ready: false,
  fleetError: false,
  relay: true,
}))

function swr(data: unknown) {
  return { data, error: undefined, isLoading: false, mutate: vi.fn() }
}
vi.mock('@console/features/admin-console/api/use-scan-policy', () => ({
  useSharedSensorsSetting: () =>
    swr({ enabled: false, new_orgs: null, ready: state.ready, version: 0 }),
  createSharedSensorEnrollmentToken: vi.fn(),
}))
vi.mock('@console/features/admin-console/api/use-instance-scan-zones', () => ({
  useInstanceScanZones: () => swr({ items: [] }),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@console/features/admin-console/components/admin-console-shell', () => ({
  useAdmin: () => ({ role: state.role }),
  useAdminOrNull: () => ({ role: state.role }),
}))
vi.mock('@console/features/admin-console/api/use-shared-fleet', () => ({
  useSharedFleet: () =>
    state.fleetError
      ? { data: undefined, error: new Error('boom'), isLoading: false, mutate: vi.fn() }
      : swr({
          sensors: [
            {
              id: 's1',
              name: 'relay-01',
              region: 'eu',
              status: 'active',
              health: 'online',
              version: 'v1.2.3',
              tools: state.relay ? ['feed.relay'] : ['nuclei'],
              current_jobs: 0,
              max_jobs: 4,
              created_at: '2026-10-01T00:00:00Z',
            },
          ],
        }),
  actOnSharedSensor: vi.fn(() => Promise.resolve()),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('Platform sensors page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    state.ready = false
    state.fleetError = false
    state.relay = true
  })

  it('puts the fleet first, enrollment behind a title-row action, the gate note behind an info mark', () => {
    state.role = 'readonly'
    render(<PlatformSensorsPage />)
    expect(screen.getByRole('button', { name: 'Enroll a sensor' })).toBeInTheDocument()
    // No enrollment form on the page itself: its fields open in a dialog.
    expect(screen.queryByLabelText('Sensor name (optional)')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Fleet' })).toBeInTheDocument()
    expect(screen.getAllByText('relay-01').length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: 'About shared scanning' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Pause/ })).not.toBeInTheDocument()
    // Pause, Resume and Retire live in the row menu, which a read-only role does not get.
    expect(
      screen.queryByRole('button', { name: /^Actions for the sensor/ })
    ).not.toBeInTheDocument()
  })

  it('names the feed relay role only when a sensor advertises it', async () => {
    const user = userEvent.setup()
    const { unmount } = render(<PlatformSensorsPage />)
    await user.click(screen.getByTestId('sensors-shared-scanning-closed'))
    expect(await screen.findByText(/feed relay/)).toBeInTheDocument()
    unmount()
    state.relay = false
    render(<PlatformSensorsPage />)
    await user.click(screen.getByTestId('sensors-shared-scanning-closed'))
    expect(await screen.findByText(/passive discovery, AI worker/)).toBeInTheDocument()
    expect(screen.queryByText(/feed relay/)).not.toBeInTheDocument()
  })

  it('drops the gate notice once shared scanning is ready', () => {
    state.ready = true
    render(<PlatformSensorsPage />)
    expect(screen.queryByTestId('sensors-shared-scanning-closed')).not.toBeInTheDocument()
  })

  it('lets a super admin pause a sensor with a reason and a code', async () => {
    state.role = 'super_admin'
    render(<PlatformSensorsPage />)
    await userEvent.click(screen.getAllByRole('button', { name: /^Actions for the sensor/ })[0])
    await userEvent.click(await screen.findByRole('menuitem', { name: /Pause/ }))
    await userEvent.type(screen.getByLabelText(/reason/i), 'maintenance window tonight')
    await userEvent.type(screen.getByLabelText(/code/i), '123456')
    await userEvent.click(screen.getByRole('button', { name: 'Pause' }))
    await waitFor(() =>
      expect(actOnSharedSensor).toHaveBeenCalledWith('s1', 'pause', {
        reason: 'maintenance window tonight',
        totp_code: '123456',
      })
    )
  })

  it('shows an error state with retry when the list fails, and keeps the rest of the page', () => {
    state.fleetError = true
    render(<PlatformSensorsPage />)
    expect(screen.getByRole('button', { name: 'Enroll a sensor' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry|try again/i })).toBeInTheDocument()
  })
})
