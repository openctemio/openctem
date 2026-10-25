import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= () => {}
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}

const perms = vi.hoisted(() => ({ granted: new Set<string>() }))
const api = vi.hoisted(() => ({
  expect: vi.fn(),
  expectation: { data: undefined as unknown },
  templateCodes: [] as (string | null)[],
  sensor: undefined as unknown,
}))

vi.mock('@/lib/permissions', () => ({
  Permission: {
    SensorsPair: 'sensors:pair',
    SensorsApprove: 'sensors:approve',
    SensorsRead: 'sensors:read',
    ScanZonesRead: 'zones:read',
  },
  useHasPermission: (p: string) => perms.granted.has(p),
}))
vi.mock('@/lib/api/scan-zone-hooks', () => ({ useScanZones: () => ({ data: { data: [] } }) }))
vi.mock('@/lib/api/sensor-hooks', () => ({
  invalidateSensorsCache: vi.fn(async () => undefined),
  useSensor: (id: string | null) => ({ data: id ? api.sensor : undefined }),
}))
vi.mock('@/lib/api/sensor-pairing-hooks', () => ({
  lookupPairing: vi.fn(),
  approvePairing: vi.fn(),
  rejectPairing: vi.fn(),
  createPairingExpectation: api.expect,
  pairingSettled: (s?: string) => ['approved', 'completed', 'denied', 'expired'].includes(s ?? ''),
  usePairingExpectation: (id: string | null) =>
    id ? api.expectation : { data: undefined, error: undefined },
  useSensorInstallTemplates: (code: string | null) => {
    api.templateCodes.push(code)
    const c = code ? `\n  -e SENSOR_PAIRING_CODE='${code}' \\` : ''
    return {
      isLoading: false,
      data: {
        docker: `docker run -d --read-only --cap-drop ALL \\${c}\n  ghcr.io/openctemio/sensor:v1`,
        compose: 'services: {}',
        kubernetes: 'kind: Deployment',
        cli: 'sudo systemctl enable --now openctem-sensor',
        policy: 'apiVersion: openctem.io/sensor-policy/v1',
        api_url: 'https://ctem.example.test',
      },
      mutate: vi.fn(),
    }
  },
}))

import { AddSensorButton } from '../add-sensor-dialog'
import { SensorOnboardingPanel } from '../sensor-onboarding-panel'
import { onboardingStage } from '../../lib/onboarding'

const future = () => new Date(Date.now() + 9 * 60_000).toISOString()

describe('SensorOnboardingPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    perms.granted = new Set(['sensors:pair', 'sensors:approve'])
    api.expectation = { data: undefined }
    api.templateCodes = []
    api.sensor = undefined
  })

  it('creates a code first, puts it in the command and waits for the sensor', async () => {
    api.expect.mockResolvedValue({
      id: 'e1',
      mode: 'reverse',
      status: 'expecting',
      code: 'K7QM4ZTD',
      expires_at: future(),
    })
    const user = userEvent.setup()
    const { rerender } = render(<SensorOnboardingPanel />)
    // No command before a code exists in this path: it would pair nothing.
    expect(screen.queryByText(/docker run/)).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Create pairing code' }))
    expect(api.expect).toHaveBeenCalledWith({})
    expect(await screen.findByText(/SENSOR_PAIRING_CODE='K7QM-4ZTD'/)).toBeInTheDocument()
    expect(api.templateCodes).toContain('K7QM-4ZTD')
    const status = screen.getByTestId('onboarding-status')
    expect(status.querySelector('[aria-current="step"]')).toHaveTextContent(
      'Waiting for the sensor'
    )

    // The sensor attached: the fingerprint to compare replaces the command.
    api.expectation = {
      data: {
        id: 'e1',
        mode: 'reverse',
        status: 'pending',
        sas: '512 · tiger · violet · anchor',
        host_facts: { hostname: 'dmz-01' },
        expires_at: future(),
        step_up: 'totp',
      },
    }
    await act(async () => rerender(<SensorOnboardingPanel />))
    expect(await screen.findByTestId('pairing-fingerprint')).toHaveTextContent('tiger')
    expect(screen.queryByText(/docker run/)).toBeNull()
    expect(
      screen.getByTestId('onboarding-status').querySelector('[aria-current="step"]')
    ).toHaveTextContent('Compare fingerprint')
  })

  it('switches the command with the platform', async () => {
    api.expect.mockResolvedValue({
      id: 'e1',
      status: 'expecting',
      code: 'K7QM4ZTD',
      expires_at: future(),
    })
    const user = userEvent.setup()
    render(<SensorOnboardingPanel />)
    await user.click(screen.getByRole('button', { name: 'Create pairing code' }))
    await screen.findByText(/docker run/)
    await user.click(screen.getByRole('radio', { name: 'Linux service' }))
    expect(screen.getByText(/systemctl enable --now openctem-sensor/)).toBeInTheDocument()
    await user.click(screen.getByRole('radio', { name: 'Kubernetes' }))
    expect(screen.getByText('kind: Deployment')).toBeInTheDocument()
    expect(screen.getByText(/a code pairs one sensor/i)).toBeInTheDocument()
  })

  it('pairs interactively: command without a code, then the code entry', async () => {
    const user = userEvent.setup()
    render(<SensorOnboardingPanel />)
    await user.click(screen.getByLabelText(/pair a sensor that shows a code/i))
    expect(screen.getByText(/docker run/)).toBeInTheDocument()
    expect(screen.queryByText(/SENSOR_PAIRING_CODE/)).toBeNull()
    expect(api.templateCodes).toContain(null)
    expect(screen.getByLabelText('Pairing code')).toBeInTheDocument()
  })

  it('offers the key install only where it is allowed', async () => {
    const onKey = vi.fn()
    const { unmount } = render(<SensorOnboardingPanel canInstallWithKey onInstallWithKey={onKey} />)
    await userEvent.click(screen.getByRole('button', { name: 'Install with an API key instead' }))
    expect(onKey).toHaveBeenCalled()
    unmount()
    render(<SensorOnboardingPanel canInstallWithKey={false} onInstallWithKey={onKey} />)
    expect(screen.queryByRole('button', { name: /api key/i })).toBeNull()
  })

  it('lists troubleshooting by what the sensor log says, with a reachability check', async () => {
    render(<SensorOnboardingPanel />)
    await userEvent.click(screen.getByRole('button', { name: 'Troubleshooting' }))
    expect(screen.getByText("The sensor's clock is wrong")).toBeInTheDocument()
    expect(
      screen.getByText('pairing: the request expired before it was approved')
    ).toBeInTheDocument()
    expect(screen.getByText("curl -fsS 'https://ctem.example.test/health'")).toBeInTheDocument()
  })
})

describe('onboardingStage', () => {
  const now = Date.now()
  it('walks waiting, compare, approved, online and ends on expiry or refusal', () => {
    expect(onboardingStage(null, { now })).toBe('start')
    expect(onboardingStage({ status: 'expecting', expires_at: future() } as never, { now })).toBe(
      'waiting'
    )
    expect(
      onboardingStage({ status: 'pending', sas: '1 · a', expires_at: future() } as never, { now })
    ).toBe('compare')
    expect(onboardingStage(null, { now, approvedSensorId: 's1' })).toBe('approved')
    expect(onboardingStage(null, { now, approvedSensorId: 's1', sensorSeen: true })).toBe('online')
    expect(
      onboardingStage(
        { status: 'expecting', expires_at: new Date(now - 1000).toISOString() } as never,
        {
          now,
        }
      )
    ).toBe('ended')
    expect(onboardingStage({ status: 'denied' } as never, { now })).toBe('ended')
  })
})

describe('AddSensorButton', () => {
  it('is hidden without sensors:pair', () => {
    perms.granted = new Set(['sensors:write'])
    const { container } = render(<AddSensorButton onClick={() => {}} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows with sensors:pair', () => {
    perms.granted = new Set(['sensors:pair'])
    render(<AddSensorButton onClick={() => {}} />)
    expect(screen.getByRole('button', { name: 'Add sensor' })).toBeInTheDocument()
  })
})
