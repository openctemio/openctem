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

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 'org-1', slug: 'acme', name: 'Acme', role: 'owner' } }),
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

  it('opens on one command whose code finds the sensor, with no choice of flow', async () => {
    api.expect.mockResolvedValue({
      id: 'e1',
      mode: 'reverse',
      status: 'expecting',
      code: 'K7QM4ZTD',
      expires_at: future(),
    })
    const { rerender } = render(<SensorOnboardingPanel />)
    // The dialog makes the command's code at once: one per opened dialog.
    expect(await screen.findByText(/SENSOR_PAIRING_CODE='K7QM-4ZTD'/)).toBeInTheDocument()
    expect(api.expect).toHaveBeenCalledTimes(1)
    expect(api.expect).toHaveBeenCalledWith({})
    expect(api.templateCodes).toContain('K7QM-4ZTD')
    // One path: no "how should it join" choice, no code box in the dialog.
    expect(screen.queryByText(/how should it join/i)).toBeNull()
    expect(screen.queryByLabelText('Pairing code')).toBeNull()
    expect(screen.getByText(/finds it by itself/i)).toBeInTheDocument()
    const status = screen.getByTestId('onboarding-status')
    expect(status.querySelector('[aria-current="step"]')).toHaveTextContent(
      'Waiting for the sensor'
    )

    // The sensor attached: the fingerprint pick replaces the command.
    api.expectation = {
      data: {
        id: 'e1',
        mode: 'reverse',
        status: 'pending',
        sas: '512 · tiger · violet · anchor',
        fingerprint_choices: [
          '108 · apple · river · stone',
          '512 · tiger · violet · anchor',
          '733 · cloud · ember · north',
        ],
        host_facts: { hostname: 'dmz-01' },
        expires_at: future(),
        step_up: 'totp',
      },
    }
    await act(async () => rerender(<SensorOnboardingPanel />))
    expect(await screen.findAllByRole('radio', { name: /tiger|apple|cloud/ })).toHaveLength(3)
    expect(screen.queryByText(/docker run/)).toBeNull()
    expect(
      screen.getByTestId('onboarding-status').querySelector('[aria-current="step"]')
    ).toHaveTextContent('Pick fingerprint')
    expect(api.expect).toHaveBeenCalledTimes(1)
  })

  it('makes no code on a page view: the inline panel waits for a click', async () => {
    api.expect.mockResolvedValue({
      id: 'e1',
      status: 'expecting',
      code: 'K7QM4ZTD',
      expires_at: future(),
    })
    const user = userEvent.setup()
    render(<SensorOnboardingPanel autoStart={false} />)
    expect(api.expect).not.toHaveBeenCalled()
    expect(screen.queryByText(/docker run/)).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Show the command' }))
    expect(await screen.findByText(/SENSOR_PAIRING_CODE='K7QM-4ZTD'/)).toBeInTheDocument()
    expect(api.expect).toHaveBeenCalledTimes(1)
  })

  it('says why no sensor arrived: the last refused attempt on the code, with the next step', async () => {
    api.expect.mockResolvedValue({
      id: 'e1',
      mode: 'reverse',
      status: 'expecting',
      code: 'K7QM4ZTD',
      expires_at: future(),
    })
    const { rerender } = render(<SensorOnboardingPanel />)
    await screen.findByText(/SENSOR_PAIRING_CODE='K7QM-4ZTD'/)
    expect(screen.queryByTestId('pairing-refusal')).toBeNull()
    for (const [refusal, title, fix] of [
      [
        { reason: 'clock_skew', at: new Date().toISOString(), clock_offset_seconds: -300 },
        'its clock is 300 seconds behind',
        'chronyc makestep',
      ],
      [
        { reason: 'key_registered', at: new Date().toISOString() },
        'its key is already registered to a sensor',
        'use Re-pair on that sensor',
      ],
      [
        { reason: 'key_busy', at: new Date().toISOString() },
        'still has another pairing request open',
        'Leave the sensor running',
      ],
    ] as const) {
      api.expectation = {
        data: {
          id: 'e1',
          mode: 'reverse',
          status: 'expecting',
          code: 'K7QM4ZTD',
          expires_at: future(),
          last_refusal: refusal,
        },
      }
      await act(async () => rerender(<SensorOnboardingPanel />))
      const notice = await screen.findByTestId('pairing-refusal')
      expect(notice).toHaveTextContent(title)
      expect(notice).toHaveTextContent(fix)
    }
  })

  it('switches the command with the platform and keeps the code', async () => {
    api.expect.mockResolvedValue({
      id: 'e1',
      status: 'expecting',
      code: 'K7QM4ZTD',
      expires_at: future(),
    })
    const user = userEvent.setup()
    render(<SensorOnboardingPanel />)
    await screen.findByText(/docker run/)
    await user.click(screen.getByRole('radio', { name: 'Linux service' }))
    expect(screen.getByText(/systemctl enable --now openctem-sensor/)).toBeInTheDocument()
    await user.click(screen.getByRole('radio', { name: 'Kubernetes' }))
    expect(screen.getByText('kind: Deployment')).toBeInTheDocument()
    expect(api.expect).toHaveBeenCalledTimes(1)
  })

  it('offers the narrowing policy as optional and links the approve page', async () => {
    api.expect.mockResolvedValue({
      id: 'e1',
      status: 'expecting',
      code: 'K7QM4ZTD',
      expires_at: future(),
    })
    render(<SensorOnboardingPanel />)
    await screen.findByText(/docker run/)
    expect(screen.getByText('Narrow it on this host (optional)')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /open the approve page/i })).toHaveAttribute(
      'href',
      '/activate'
    )
  })

  it('says what to do when the code expired, and makes a new command', async () => {
    api.expect.mockResolvedValue({
      id: 'e1',
      status: 'expecting',
      code: 'K7QM4ZTD',
      expires_at: new Date(Date.now() - 1000).toISOString(),
    })
    const user = userEvent.setup()
    render(<SensorOnboardingPanel />)
    expect(
      await screen.findByText(/the sensor shows a link: open it to approve/i)
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'New command' }))
    expect(api.expect).toHaveBeenCalledTimes(2)
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
