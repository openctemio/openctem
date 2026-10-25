import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiClientError } from '@/lib/api/error-handler'
import type { SensorGrant } from '@/lib/api/sensor-grant-hooks'

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
  grant: null as unknown,
  update: vi.fn(),
  mutate: vi.fn(async () => undefined),
  toastError: vi.fn(),
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: api.toastError } }))
vi.mock('@/lib/permissions', () => ({
  Permission: {
    SensorsRead: 'sensors:read',
    SensorsGrantNarrow: 'sensors:grant:narrow',
    SensorsGrantWiden: 'sensors:grant:widen',
    ScanZonesRead: 'zones:read',
  },
  useHasPermission: (p: string) => perms.granted.has(p),
}))
vi.mock('@/lib/api/scan-zone-hooks', () => ({
  useScanZones: () => ({ data: { data: [{ id: 'z1', name: 'dmz' }] } }),
}))
vi.mock('@/lib/api/sensor-grant-hooks', async (orig) => {
  const real = await orig<typeof import('@/lib/api/sensor-grant-hooks')>()
  return {
    ...real,
    useSensorGrant: () => ({ data: api.grant, error: undefined, mutate: api.mutate }),
    useSensorGrantProfiles: () => ({
      data: {
        profiles: [
          {
            name: 'easm-external',
            job_types: ['scan'],
            tier_ceiling: 1,
            target_network: 'public',
            allow_credentials: false,
            allow_push_ingest: false,
            default: false,
            parameterised: false,
          },
        ],
      },
    }),
    updateSensorGrant: api.update,
    useSensorGrantSuggestion: () => ({ data: undefined, mutate: api.mutate }),
  }
})

import { SensorGrantSection } from '../sensor-grant-section'
import { SensorGrantTags } from '../sensor-cells'

function grant(over: Partial<SensorGrant> = {}): SensorGrant {
  return {
    sensor_id: 's1',
    profile: 'internal-network-scanner',
    legacy_broad: false,
    trust_level: 'new',
    job_types: ['scan', 'validate'],
    zone_ids: ['z1'],
    tools: null,
    capabilities: [],
    tier_ceiling: 1,
    target_network: 'any',
    target_cidrs: null,
    target_domains: null,
    allow_credentials: false,
    allow_push_ingest: false,
    remote_actions: [],
    version: 3,
    effective: { tier_ceiling: 0, allow_credentials: false, allow_push_ingest: false },
    ...over,
  }
}

function row(label: string) {
  const dt = within(screen.getByTestId('sensor-grant')).getByText(label)
  return dt.nextElementSibling as HTMLElement
}

describe('SensorGrantSection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    perms.granted = new Set([
      'sensors:read',
      'sensors:grant:narrow',
      'sensors:grant:widen',
      'zones:read',
    ])
    api.grant = grant()
  })

  it('shows null as Any and [] as None, zones by name, and the cap while New', () => {
    render(<SensorGrantSection sensorId="s1" />)
    expect(row('Tools')).toHaveTextContent('Any')
    expect(row('Capabilities')).toHaveTextContent('None')
    expect(row('Zones')).toHaveTextContent('dmz')
    expect(row('Job types')).toHaveTextContent('scan, validate')
    expect(row('Target scope')).toHaveTextContent('Any')
    expect(row('Tier ceiling')).toHaveTextContent('T0: passive while New')
  })

  it('words the remote actions: pause and drain always, the rest as granted', () => {
    render(<SensorGrantSection sensorId="s1" />)
    expect(row('Remote actions')).toHaveTextContent('Pause and drain: always allowed')
    expect(row('Remote actions')).toHaveTextContent('Nothing else')
    expect(row('Remote actions').textContent).not.toMatch(/rotate_key|\u00b7/)
  })

  it('names granted remote actions in words, never as identifiers', () => {
    api.grant = grant({ remote_actions: ['rotate_key', 'diagnostics'] })
    render(<SensorGrantSection sensorId="s1" />)
    expect(row('Remote actions')).toHaveTextContent(/Also allowed: key rotation.*diagnostics/)
  })

  it('flags a legacy broad grant', () => {
    api.grant = grant({ profile: 'legacy-broad', legacy_broad: true, trust_level: 'trusted' })
    render(<SensorGrantSection sensorId="s1" />)
    expect(screen.getByTestId('legacy-broad-warning')).toHaveTextContent(
      'Legacy broad grant: narrow it'
    )
    expect(screen.getByRole('button', { name: /narrow/i })).toBeInTheDocument()
  })

  it('hides Promote without sensors:grant:widen', () => {
    perms.granted = new Set(['sensors:read', 'sensors:grant:narrow'])
    render(<SensorGrantSection sensorId="s1" />)
    expect(screen.queryByRole('button', { name: /promote/i })).not.toBeInTheDocument()
  })

  it('promotes after a confirmation that explains what New means', async () => {
    api.update.mockResolvedValue(grant({ trust_level: 'trusted', version: 4 }))
    const user = userEvent.setup()
    render(<SensorGrantSection sensorId="s1" />)
    await user.click(screen.getByRole('button', { name: /promote to trusted/i }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent(/passive work only/i)
    expect(dialog).toHaveTextContent(/no credentials/i)
    await user.click(within(dialog).getByRole('button', { name: /^promote$/i }))
    await waitFor(() => expect(api.update).toHaveBeenCalledTimes(1))
    expect(api.update.mock.calls[0][1]).toMatchObject({
      version: 3,
      trust_level: 'trusted',
      tools: null,
      capabilities: [],
    })
  })

  it('shows the server 403 message when a widening is refused', async () => {
    api.update.mockRejectedValue(
      new ApiClientError(
        "Widening a sensor's grant or promoting it needs the sensors:grant:widen permission",
        'FORBIDDEN',
        403
      )
    )
    const user = userEvent.setup()
    render(<SensorGrantSection sensorId="s1" />)
    await user.click(screen.getByRole('button', { name: /promote to trusted/i }))
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: /^promote$/i })
    )
    await waitFor(() =>
      expect(api.toastError).toHaveBeenCalledWith(
        "Widening a sensor's grant or promoting it needs the sensors:grant:widen permission"
      )
    )
  })

  it('reloads the grant on a version conflict', async () => {
    api.update.mockRejectedValue(new ApiClientError('stale', 'CONFLICT', 409))
    const user = userEvent.setup()
    render(<SensorGrantSection sensorId="s1" />)
    await user.click(screen.getByRole('button', { name: /promote to trusted/i }))
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: /^promote$/i })
    )
    await waitFor(() => expect(api.mutate).toHaveBeenCalledWith())
    expect(api.toastError).toHaveBeenCalledWith(expect.stringMatching(/reloaded/i))
  })

  it('edit form warns when a change widens, and shows the server 403 in the dialog', async () => {
    perms.granted = new Set(['sensors:read', 'sensors:grant:narrow', 'zones:read'])
    api.update.mockRejectedValue(
      new ApiClientError('needs the sensors:grant:widen permission', 'FORBIDDEN', 403)
    )
    const user = userEvent.setup()
    render(<SensorGrantSection sensorId="s1" />)
    await user.click(screen.getByRole('button', { name: /^edit$/i }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByTestId('grant-widens')).not.toBeInTheDocument()
    await user.click(within(dialog).getByLabelText(/may receive jobs with credentials/i))
    expect(within(dialog).getByTestId('grant-widens')).toHaveTextContent(/credentials/)
    expect(within(dialog).getByTestId('grant-widens')).toHaveTextContent(/only narrow/i)
    await user.click(within(dialog).getByRole('button', { name: /^save$/i }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(
      'needs the sensors:grant:widen permission'
    )
    expect(api.update.mock.calls[0][1]).toMatchObject({ allow_credentials: true, version: 3 })
  })

  it('narrowing a list from Any to Only these sends an empty list, not null', async () => {
    api.update.mockResolvedValue(grant({ tools: [] }))
    const user = userEvent.setup()
    render(<SensorGrantSection sensorId="s1" />)
    await user.click(screen.getByRole('button', { name: /^edit$/i }))
    const dialog = await screen.findByRole('dialog')
    const tools = within(dialog).getByRole('group', { name: 'Tools' })
    await user.click(within(tools).getByRole('button', { name: 'Only these' }))
    expect(within(dialog).queryByTestId('grant-widens')).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: /^save$/i }))
    await waitFor(() => expect(api.update).toHaveBeenCalledTimes(1))
    expect(api.update.mock.calls[0][1].tools).toEqual([])
  })

  describe('a collector whose reports are refused', () => {
    const collectorGrant = (over: Partial<SensorGrant> = {}) =>
      grant({
        profile: 'collector',
        job_types: ['collect', 'connector_sync'],
        tier_ceiling: 0,
        target_network: 'none',
        allow_push_ingest: true,
        ...over,
      })

    it('says an untrusted collector is refused for trust, and links the promotion', async () => {
      api.grant = collectorGrant()
      const user = userEvent.setup()
      render(<SensorGrantSection sensorId="s1" sensorType="collector" />)
      const callout = screen.getByTestId('collector-refused')
      expect(callout).toHaveAttribute('data-missing', 'trust')
      expect(callout).toHaveTextContent(/reports are refused: it is not trusted/i)
      expect(callout).toHaveTextContent(/refuses every report/i)
      await user.click(within(callout).getByRole('button', { name: /promote to trusted/i }))
      expect(await screen.findByRole('alertdialog')).toHaveTextContent(/promote this sensor/i)
    })

    it('says a collector without push ingest in its grant is refused for the grant', async () => {
      api.grant = collectorGrant({
        profile: 'internal-network-scanner',
        allow_push_ingest: false,
        job_types: ['scan'],
      })
      const user = userEvent.setup()
      render(<SensorGrantSection sensorId="s1" sensorType="collector" />)
      const callout = screen.getByTestId('collector-refused')
      expect(callout).toHaveAttribute('data-missing', 'grant')
      expect(callout).toHaveTextContent(/its grant does not allow them/i)
      await user.click(within(callout).getByRole('button', { name: /edit the grant/i }))
      expect(await screen.findByRole('dialog')).toBeInTheDocument()
    })

    it('without sensors:grant:widen: explains, offers no action', () => {
      perms.granted = new Set(['sensors:read', 'sensors:grant:narrow'])
      api.grant = collectorGrant()
      render(<SensorGrantSection sensorId="s1" sensorType="collector" />)
      const callout = screen.getByTestId('collector-refused')
      expect(within(callout).queryByRole('button')).not.toBeInTheDocument()
      expect(callout).toHaveTextContent(/administrator who may widen/i)
    })

    it('says nothing for a trusted collector or a scanner', () => {
      api.grant = collectorGrant({
        trust_level: 'trusted',
        effective: { tier_ceiling: 0, allow_credentials: false, allow_push_ingest: true },
      })
      const { unmount } = render(<SensorGrantSection sensorId="s1" sensorType="collector" />)
      expect(screen.queryByTestId('collector-refused')).not.toBeInTheDocument()
      unmount()
      api.grant = grant()
      render(<SensorGrantSection sensorId="s1" sensorType="worker" />)
      expect(screen.queryByTestId('collector-refused')).not.toBeInTheDocument()
    })
  })

  it('renders nothing without sensors:read', () => {
    perms.granted = new Set()
    const { container } = render(<SensorGrantSection sensorId="s1" />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('SensorGrantTags', () => {
  it('flags legacy broad and New', () => {
    render(
      <SensorGrantTags
        grant={{ sensor_id: 's', profile: 'legacy-broad', trust_level: 'new', legacy_broad: true }}
      />
    )
    expect(screen.getByText('Legacy broad grant')).toBeInTheDocument()
    expect(screen.getByText('New')).toBeInTheDocument()
  })

  it('shows nothing for a trusted narrow grant or without a summary', () => {
    const { container, rerender } = render(
      <SensorGrantTags
        grant={{
          sensor_id: 's',
          profile: 'easm-external',
          trust_level: 'trusted',
          legacy_broad: false,
        }}
      />
    )
    expect(container).toBeEmptyDOMElement()
    rerender(<SensorGrantTags />)
    expect(container).toBeEmptyDOMElement()
  })
})
