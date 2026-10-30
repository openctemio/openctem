import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { DEFAULT_CONNECTOR_SETTINGS, type ConnectorSettings } from '../../../lib/tenable-sc'

/**
 * License rotation in the connector dialog and the coverage panel, and "scan
 * now" with a connector (api research/143 §4-§5).
 */

const mockResume = vi.fn()
const mockScanNow = vi.fn()
const mockPush = vi.fn()
const state = vi.hoisted(() => ({
  canManage: true,
  perms: ['scans:write', 'integrations:read'] as string[],
  integrations: [] as unknown[],
}))

vi.mock('@/features/integrations/api/use-integrations-api', () => ({
  useResumeCoverageRotationApi: () => ({ trigger: mockResume, isMutating: false }),
  useConnectorScanNowApi: () => ({ trigger: mockScanNow, isMutating: false }),
  useSecurityIntegrationsApi: (enabled: boolean) => ({
    data: enabled ? { data: state.integrations } : undefined,
  }),
  useCreateIntegrationApi: () => ({ trigger: vi.fn(), isMutating: false }),
  useUpdateIntegrationApi: () => ({ trigger: vi.fn(), isMutating: false }),
}))
vi.mock('@/lib/api/scan-coverage-hooks', () => ({
  useScanCoverage: () => ({ data: undefined, isLoading: false }),
}))
vi.mock('@/lib/api/sensor-hooks', () => ({
  useAllSensors: () => ({ data: { items: [] }, isLoading: false }),
}))
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: mockPush }) }))
const toastSuccess = vi.fn()
const toastError = vi.fn()
vi.mock('sonner', () => ({
  toast: {
    success: (...a: unknown[]) => toastSuccess(...a),
    error: (...a: unknown[]) => toastError(...a),
  },
}))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children, permission }: { children: React.ReactNode; permission: string }) =>
    permission === 'integrations:manage' && !state.canManage ? null : children,
  usePermissions: () => ({ can: (p: string) => state.perms.includes(p) }),
  Permission: {
    IntegrationsManage: 'integrations:manage',
    IntegrationsRead: 'integrations:read',
    ScansWrite: 'scans:write',
  },
}))

import { TenableCoveragePanel } from '../tenable-coverage-panel'
import { RotationFields } from '../tenable-connector-dialog'
import { TenableScanNowButton } from '../tenable-scan-now'
import type { Integration } from '@/features/integrations/types/integration.types'

const STALLED =
  'rotation stalled: the previous batch failed after it launched, so its results may not be ingested; an administrator resumes rotation to recycle the rotation repository'

function connector(
  id: string,
  config: Record<string, unknown> = {},
  sync: Record<string, unknown> = {}
): Integration {
  return {
    id,
    name: `Tenable.sc ${id}`,
    provider: 'tenable',
    category: 'security',
    status: 'connected',
    auth_type: 'api_key',
    config: {
      engine: 'tenable_sc',
      execution_mode: 'sensor',
      sensor_id: 's1',
      coverage_enabled: true,
      ...config,
    },
    metadata: { tenable_sync: { licensed_ips: 100, active_ips: 40, ...sync } },
  } as unknown as Integration
}

beforeEach(() => {
  state.canManage = true
  state.perms = ['scans:write', 'integrations:read']
  state.integrations = []
  mockResume.mockReset()
  mockScanNow.mockReset()
  mockPush.mockReset()
  toastSuccess.mockReset()
  toastError.mockReset()
})

describe('RotationFields', () => {
  function Harness({ initial }: { initial: Partial<ConnectorSettings> }) {
    const settings = { ...DEFAULT_CONNECTOR_SETTINGS, ...initial }
    return <RotationFields settings={settings} onChange={onChange} />
  }
  const onChange = vi.fn()

  it('off: explains it and asks for no acknowledgement', () => {
    render(<Harness initial={{ rotation: 'off' }} />)
    expect(screen.getByTestId('tsc-rotation-hint')).toHaveTextContent(
      /Covers what the license holds/
    )
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/Wait after a batch/)).not.toBeInTheDocument()
  })

  it('aging: the acknowledgement and the wait hours', () => {
    render(<Harness initial={{ rotation: 'aging' }} />)
    expect(screen.getByTestId('tsc-rotation-hint')).toHaveTextContent(/nightly cleanup/)
    const ack = screen.getByRole('checkbox')
    expect(ack).not.toBeChecked()
    fireEvent.click(ack)
    expect(onChange).toHaveBeenCalledWith({ rotationAcknowledged: true })
    const wait = screen.getByLabelText(/Wait after a batch/) as HTMLInputElement
    expect(wait.value).toBe('12')
    fireEvent.change(wait, { target: { value: '24' } })
    expect(onChange).toHaveBeenCalledWith({ rotationWaitHours: 24 })
  })

  it('recycle: the acknowledgement, no wait', () => {
    render(<Harness initial={{ rotation: 'recycle', rotationAcknowledged: true }} />)
    expect(screen.getByRole('checkbox')).toBeChecked()
    expect(screen.getByText(/license terms allow rotating more assets/)).toBeInTheDocument()
    expect(screen.queryByLabelText(/Wait after a batch/)).not.toBeInTheDocument()
  })
})

describe('TenableCoveragePanel rotation', () => {
  it('shows the mode, the cycle progress and why the next batch waits', () => {
    const later = new Date(Date.now() + 3 * 3600_000).toISOString()
    render(
      <TenableCoveragePanel
        integration={connector(
          'c1',
          { coverage_rotation: 'aging', coverage_rotation_acknowledged: true },
          {
            cycle: 2,
            cycle_assessed: 30,
            cycle_eligible: 120,
            cycle_eta: '2026-10-20T00:00:00Z',
            next_batch_at: later,
            coverage_wait:
              "the rotation repository's license is freed by Tenable.sc's nightly cleanup",
          }
        )}
      />
    )
    expect(screen.getByText('Cycle 2: 30 / 120')).toBeInTheDocument()
    expect(
      screen.getByRole('meter', { name: '30 of 120 assets assessed in this cycle' })
    ).toBeInTheDocument()
    const line = screen.getByTestId('tsc-rotation-line')
    expect(line).toHaveTextContent('License rotation: Aging')
    expect(line).toHaveTextContent(/next batch from/)
    expect(line).toHaveTextContent(/nightly cleanup frees the license of the last batch/)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('a stalled rotation: the reason and Resume for managers, after a confirmation', async () => {
    const onChanged = vi.fn()
    mockResume.mockResolvedValue({})
    render(
      <TenableCoveragePanel
        integration={connector(
          'c1',
          { coverage_rotation: 'recycle', coverage_rotation_acknowledged: true },
          { rotation_stalled: STALLED }
        )}
        onChanged={onChanged}
      />
    )
    expect(screen.getByRole('alert')).toHaveTextContent(/Rotation stalled/)
    fireEvent.click(screen.getByRole('button', { name: 'Resume rotation' }))
    expect(mockResume).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    fireEvent.click(
      Array.from(dialog.querySelectorAll('button')).find(
        (b) => b.textContent === 'Resume rotation'
      )!
    )
    await waitFor(() => expect(mockResume).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
  })

  it('no Resume without integrations:manage', () => {
    state.canManage = false
    render(
      <TenableCoveragePanel
        integration={connector(
          'c1',
          { coverage_rotation: 'recycle' },
          { rotation_stalled: STALLED }
        )}
      />
    )
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Resume rotation' })).not.toBeInTheDocument()
  })
})

describe('TenableScanNowButton', () => {
  it('renders nothing without a connector', () => {
    state.integrations = [{ ...connector('n1'), config: { engine: 'nessus_pro' } }]
    const { container } = render(<TenableScanNowButton assetIds={['a1']} label="Scan" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing without scans:write or integrations:read', () => {
    state.integrations = [connector('c1')]
    state.perms = ['integrations:read']
    const { container, unmount } = render(<TenableScanNowButton assetIds={['a1']} label="Scan" />)
    expect(container).toBeEmptyDOMElement()
    unmount()
    state.perms = ['scans:write']
    const again = render(<TenableScanNowButton assetIds={['a1']} label="Scan" />)
    expect(again.container).toBeEmptyDOMElement()
  })

  it('a disabled connector is not offered', () => {
    state.integrations = [{ ...connector('c1'), status: 'disabled' }]
    const { container } = render(<TenableScanNowButton assetIds={['a1']} label="Scan" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('one connector: scans the assets with it and links to the run', async () => {
    state.integrations = [connector('c1')]
    mockScanNow.mockResolvedValue({ id: 'run-1', status: 'running' })
    render(<TenableScanNowButton assetIds={['a1']} label="Scan with Tenable.sc" />)
    fireEvent.click(screen.getByRole('button', { name: 'Scan with Tenable.sc' }))
    // It sends scan traffic now: the user confirms first.
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Scan this asset with Tenable.sc c1?')
    expect(mockScanNow).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Scan asset' }))
    await waitFor(() =>
      expect(mockScanNow).toHaveBeenCalledWith({ integrationId: 'c1', assetIds: ['a1'] })
    )
    await waitFor(() => expect(toastSuccess).toHaveBeenCalled())
    const opts = toastSuccess.mock.calls[0][1] as { action: { onClick: () => void } }
    opts.action.onClick()
    expect(mockPush).toHaveBeenCalledWith('/scans/runs?run=run-1')
  })

  it('Cancel on the scan question starts no scan', async () => {
    state.integrations = [connector('c1')]
    render(<TenableScanNowButton assetIds={['a1', 'a2']} label="Scan" />)
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))
    expect(await screen.findByRole('alertdialog')).toHaveTextContent('Scan 2 assets with')
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(mockScanNow).not.toHaveBeenCalled()
  })

  it("an API refusal is shown with the API's message", async () => {
    state.integrations = [connector('c1')]
    mockScanNow.mockRejectedValue(new Error('the connector sensor is not active'))
    render(<TenableScanNowButton assetIds={['a1']} label="Scan" />)
    fireEvent.click(screen.getByRole('button', { name: 'Scan' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Scan asset' }))
    await waitFor(() => expect(toastError).toHaveBeenCalled())
  })

  it('several connectors: the caller picks one', async () => {
    state.integrations = [connector('c1'), connector('c2')]
    mockScanNow.mockResolvedValue({ id: 'run-2', status: 'running' })
    render(<TenableScanNowButton assetIds={['a1']} label="Scan" />)
    await userEvent.click(screen.getByRole('button', { name: 'Scan' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Tenable.sc c2' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Scan asset' }))
    await waitFor(() =>
      expect(mockScanNow).toHaveBeenCalledWith({ integrationId: 'c2', assetIds: ['a1'] })
    )
  })
})
