import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import type { Sensor, SensorPosture } from '@/lib/api/sensor-types'

import { SensorNameCell, SensorPostureTag } from '../sensor-cells'
import { SensorPostureSection } from '../sensor-posture'

const weak: SensorPosture = {
  local_policy: 'absent_legacy',
  platform_pin: 'none',
  network_enforced: false,
  unhardened: ['policy_none', 'pin_none', 'network_unenforced'],
}
const hardened: SensorPosture = {
  local_policy: 'enforced',
  platform_pin: 'fingerprint',
  network_enforced: true,
  unhardened: [],
}

describe('SensorPostureTag', () => {
  it('flags an unhardened sensor with the fixes in its title', () => {
    const { container } = render(<SensorPostureTag sensor={{ posture: weak }} />)
    expect(screen.getByText('Unhardened')).toBeInTheDocument()
    const title = container.querySelector('[title]')?.getAttribute('title') ?? ''
    expect(title).toContain('Pin the platform CA with SENSOR_CA_FINGERPRINT.')
    expect(title).toContain('SENSOR_SANDBOX_NETWORK=required')
  })

  it('shows nothing for a hardened sensor or an API without the posture', () => {
    const { container, rerender } = render(<SensorPostureTag sensor={{ posture: hardened }} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<SensorPostureTag sensor={{}} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('appears on the sensor list row', () => {
    const sensor = {
      id: 's1',
      name: 'edge',
      type: 'worker',
      status: 'active',
      posture: weak,
    } as Sensor
    const { container } = render(<SensorNameCell sensor={sensor} />)
    expect(container.querySelector('[data-slot="sensor-posture-tag"]')).not.toBeNull()
  })
})

describe('SensorPostureSection', () => {
  it('lists each weakness with its fix', () => {
    render(
      <SensorPostureSection
        sensor={{ posture: { ...weak, unhardened: [...weak.unhardened, 'bearer_key'] } }}
      />
    )
    expect(screen.getByText('Security posture')).toBeInTheDocument()
    expect(screen.getByText('This sensor runs unhardened')).toBeInTheDocument()
    const fixes = screen.getByTestId('posture-fixes')
    expect(fixes.querySelectorAll('li')).toHaveLength(4)
    expect(fixes).toHaveTextContent(
      'Install a local policy (the Local policy tab of the install commands).'
    )
    expect(screen.getByText('System trust store only')).toBeInTheDocument()
    expect(screen.getByText('Not confined')).toBeInTheDocument()
  })

  it('shows a hardened posture without a warning, and nothing without one', () => {
    const { container, rerender } = render(<SensorPostureSection sensor={{ posture: hardened }} />)
    expect(screen.queryByTestId('posture-fixes')).not.toBeInTheDocument()
    expect(screen.getByText('Pinned CA (fingerprint)')).toBeInTheDocument()
    expect(screen.getByText('Confined')).toBeInTheDocument()
    rerender(<SensorPostureSection sensor={{}} />)
    expect(container).toBeEmptyDOMElement()
  })
})
