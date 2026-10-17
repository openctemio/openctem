import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import {
  actOnSharedSensor,
  viewSharedJob,
} from '@console/features/admin-console/api/use-shared-fleet'
import SharedSensorsPage from '../page'

const state = vi.hoisted(() => ({ role: 'readonly' as string }))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@console/features/admin-console/components/admin-console-shell', () => ({
  useAdmin: () => ({ role: state.role }),
}))
const swr = (data: unknown) => ({ data, error: undefined, isLoading: false, mutate: vi.fn() })
vi.mock('@console/features/admin-console/api/use-shared-fleet', () => ({
  useSharedFleet: () =>
    swr({
      sensors: [
        {
          id: 's1',
          name: 'shared-eu-1',
          region: 'eu',
          status: 'active',
          health: 'online',
          version: 'v1.2.3',
          tools: ['nuclei'],
          current_jobs: 1,
          max_jobs: 4,
          created_at: '2026-10-01T00:00:00Z',
        },
      ],
    }),
  useSharedQueue: () =>
    swr({
      lanes: [{ tool: 'nuclei', queued: 2, running: 1 }],
      organizations: [
        {
          tenant_id: 't1',
          tenant_name: 'Acme',
          queued: 2,
          running: 1,
          completed_24h: 3,
          failed_24h: 0,
        },
      ],
    }),
  useSharedJobs: () =>
    swr({
      data: [
        {
          id: 'j1',
          tenant_id: 't1',
          tenant_name: 'Acme',
          type: 'scan',
          tool: 'nuclei',
          status: 'running',
          sensor_name: 'shared-eu-1',
          created_at: '2026-10-01T00:00:00Z',
        },
      ],
      total: 1,
      page: 1,
      per_page: 20,
      total_pages: 1,
    }),
  viewSharedJob: vi.fn(() =>
    Promise.resolve({
      job: {
        id: 'j1',
        tenant_id: 't1',
        tenant_name: 'Acme',
        type: 'scan',
        tool: 'nuclei',
        status: 'running',
        created_at: '',
      },
      targets: ['acme.example'],
      logs: [{ ts: '2026-10-01T00:00:00Z', level: 'info', msg: 'probing acme.example' }],
      logs_truncated: false,
    })
  ),
  actOnSharedSensor: vi.fn(() => Promise.resolve()),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('Shared sensors console page', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows the fleet, the queue and job metadata to a read-only administrator, with no action', () => {
    state.role = 'readonly'
    render(<SharedSensorsPage />)
    expect(screen.getAllByText('shared-eu-1').length).toBeGreaterThan(0)
    expect(screen.getByText('2 queued, 1 running')).toBeInTheDocument()
    expect(screen.getByText('2 queued, 1 running, 3 done, 0 failed')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Pause/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Retire/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Targets and logs/ })).not.toBeInTheDocument()
  })

  it('lets an operations administrator view a job only with a reason', async () => {
    state.role = 'ops_admin'
    render(<SharedSensorsPage />)
    expect(screen.queryByRole('button', { name: /Pause/ })).not.toBeInTheDocument()
    await userEvent.click(screen.getAllByRole('button', { name: /Targets and logs/ })[0])
    await userEvent.type(screen.getByLabelText(/reason/i), 'abuse report 42 from the operator')
    await userEvent.click(screen.getByRole('button', { name: 'View' }))
    await waitFor(() =>
      expect(viewSharedJob).toHaveBeenCalledWith('j1', 'abuse report 42 from the operator')
    )
    expect(await screen.findByText('acme.example')).toBeInTheDocument()
  })

  it('lets a super admin pause a shared sensor with a reason and a code', async () => {
    state.role = 'super_admin'
    render(<SharedSensorsPage />)
    await userEvent.click(screen.getAllByRole('button', { name: /Pause/ })[0])
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
})
