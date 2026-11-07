import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'

import type { Sensor } from '@/lib/api/sensor-types'
import { SENSOR_SECCOMP_PROFILE_URL, SensorFirstReport } from '../sensor-tool-review'

const base = {
  id: 's-1',
  name: 'dmz-scanner-01',
  last_seen_at: '2026-10-13T00:00:00Z',
} as unknown as Sensor

function sandbox(posture?: Sensor['posture']) {
  render(<SensorFirstReport sensor={{ ...base, posture } as Sensor} />)
  return screen.getByTestId('sandbox-check')
}

describe('install review: sandbox check', () => {
  it('a confined sensor passes, with no download', () => {
    const box = sandbox({ network_enforced: true } as Sensor['posture'])
    expect(within(box).getByText(/Confined/)).toBeInTheDocument()
    expect(within(box).queryByRole('link')).toBeNull()
  })

  it('an unconfined sensor gets the fix: the seccomp profile', () => {
    const box = sandbox({ network_enforced: false } as Sensor['posture'])
    expect(within(box).getByText(/Not confined/)).toBeInTheDocument()
    const link = within(box).getByRole('link', { name: /seccomp profile/i })
    expect(link).toHaveAttribute('href', SENSOR_SECCOMP_PROFILE_URL)
    expect(SENSOR_SECCOMP_PROFILE_URL).toBe('/api/v1/sensors/install/seccomp-profile')
  })

  it('a host without the sandbox says active tools are refused, with no seccomp download', () => {
    const box = sandbox({
      network_enforced: false,
      tools_unconfined: 'refused',
    } as Sensor['posture'])
    expect(
      within(box).getByText(/Tools that contact their targets are refused/)
    ).toBeInTheDocument()
    expect(within(box).getByText(/SENSOR_SANDBOX=off/)).toBeInTheDocument()
    expect(within(box).queryByRole('link')).toBeNull()
  })

  it('a sandbox turned off by the operator says every tool runs unconfined', () => {
    const box = sandbox({
      network_enforced: false,
      tools_unconfined: 'acknowledged',
    } as Sensor['posture'])
    expect(within(box).getByText(/every tool runs unconfined/)).toBeInTheDocument()
  })

  it('an older sensor that reports no posture says so', () => {
    const box = sandbox(undefined)
    expect(within(box).getByText(/does not report its sandbox/)).toBeInTheDocument()
  })
})
