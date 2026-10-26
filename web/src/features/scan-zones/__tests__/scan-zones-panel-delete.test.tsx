import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const api = vi.hoisted(() => ({ deleteScanZone: vi.fn() }))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Permission: {
    ScanZonesRead: 'r',
    ScanZonesWrite: 'w',
    ScanZonesDelete: 'd',
    SensorsRead: 's',
  },
  useHasPermission: () => true,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/hooks/use-url-param', () => ({ useUrlFilter: () => ['', vi.fn()] }))
vi.mock('@/lib/api/scan-zone-hooks', () => ({
  useScanZones: () => ({
    data: {
      data: [
        {
          id: 'z1',
          tenant_id: 't1',
          name: 'HQ',
          description: '',
          is_default: false,
          ranges: ['10.1.0.0/16'],
          sensor_ids: [],
          created_at: '',
          updated_at: '',
        },
      ],
    },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useScanZoneCoverage: () => ({ data: undefined, mutate: vi.fn() }),
  deleteScanZone: (...a: unknown[]) => api.deleteScanZone(...a),
  invalidateScanZonesCache: vi.fn(async () => undefined),
}))
vi.mock('../hooks/use-zone-sensors', () => ({ useZoneSensors: () => ({ byId: new Map() }) }))
vi.mock('../components/scan-zone-dialog', () => ({ ScanZoneDialog: () => null }))
vi.mock('../components/zone-sensors-dialog', () => ({ ZoneSensorsDialog: () => null }))
vi.mock('../components/zone-coverage-card', () => ({ ZoneCoverageCard: () => null }))

import { ScanZonesPanel } from '../components/scan-zones-panel'

describe('ScanZonesPanel delete', () => {
  beforeEach(() => api.deleteScanZone.mockReset().mockResolvedValue(undefined))

  it('deletes a zone only after its name is typed', async () => {
    const user = userEvent.setup()
    render(<ScanZonesPanel createOpen={false} onCreateOpenChange={vi.fn()} />)
    await user.click(screen.getByRole('button', { name: /actions for hq/i }))
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete the scan zone HQ?')
    const confirm = within(dialog).getByRole('button', { name: 'Delete zone' })
    expect(confirm).toBeDisabled()
    expect(api.deleteScanZone).not.toHaveBeenCalled()
    await user.type(within(dialog).getByRole('textbox'), 'HQ')
    await user.click(confirm)
    await waitFor(() => expect(api.deleteScanZone).toHaveBeenCalledWith('z1'))
  })
})
