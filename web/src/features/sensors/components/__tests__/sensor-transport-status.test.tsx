import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const perms = vi.hoisted(() => ({ granted: new Set<string>() }))
const api = vi.hoisted(() => ({ data: undefined as unknown }))

vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (k: string, _f?: string, p?: Record<string, string>) =>
      p?.endpoint ? `${k}:${p.endpoint}` : k,
  }),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { SensorsRead: 'sensors:read' },
  useHasPermission: (p: string) => perms.granted.has(p),
}))
vi.mock('@/lib/api/sensor-pairing-hooks', () => ({
  useSensorTransportStatus: () => ({ data: api.data }),
}))

import { SensorTransportStatusLine } from '../sensor-transport-status'

describe('SensorTransportStatusLine', () => {
  beforeEach(() => {
    perms.granted = new Set(['sensors:read'])
  })

  it('renders nothing without sensors:read', () => {
    perms.granted = new Set()
    api.data = { mode: 'auto', grpc: { state: 'advertised', endpoint: 'sensors.example.test:443' } }
    const { container } = render(<SensorTransportStatusLine />)
    expect(container).toBeEmptyDOMElement()
  })

  it('names the gRPC endpoint while it is advertised', () => {
    api.data = { mode: 'auto', grpc: { state: 'advertised', endpoint: 'sensors.example.test:443' } }
    render(<SensorTransportStatusLine />)
    expect(screen.getByTestId('sensor-transport-status')).toHaveTextContent(
      'sensors.transportStatus.grpc:sensors.example.test:443'
    )
  })

  it('shows the reason when gRPC is not reachable', () => {
    api.data = { mode: 'auto', grpc: { state: 'unavailable', reason: 'foreign_certificate' } }
    render(<SensorTransportStatusLine />)
    const el = screen.getByTestId('sensor-transport-status')
    expect(el).toHaveTextContent('sensors.transportStatus.httpsOnly')
    expect(el).toHaveTextContent('(foreign_certificate)')
  })

  it('says v3 is off', () => {
    api.data = { mode: 'off', grpc: { state: 'unavailable', reason: 'transport_off' } }
    render(<SensorTransportStatusLine />)
    const el = screen.getByTestId('sensor-transport-status')
    expect(el).toHaveTextContent('sensors.transportStatus.off')
    expect(el).not.toHaveTextContent('transport_off')
  })
})
