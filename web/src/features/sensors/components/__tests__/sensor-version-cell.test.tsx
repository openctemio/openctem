import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { SensorVersionCell, type SensorVersionFields } from '../sensor-cells'
import { sdkVersionOptions } from '../sensor-facet-panel'
import type { ReleaseChannel } from '../../lib/fleet'

const CHANNEL: ReleaseChannel = {
  products: [
    { id: 'openctemio-sensor', latest_version: 'v0.5.0', min_version: 'v0.4.0', image: '' },
    {
      id: 'openctemio-connector-tenable',
      latest_version: 'v0.2.0',
      min_version: 'v0.1.0',
      image: '',
    },
  ],
  sdkLatest: 'v0.9.0',
}

function cell(sensor: SensorVersionFields, channel: ReleaseChannel = CHANNEL) {
  const { container } = render(<SensorVersionCell sensor={sensor} channel={channel} />)
  return container
}

describe('SensorVersionCell', () => {
  it('shows the version over the SDK, with the build facts in the tooltip', () => {
    const c = cell({
      version: '0.5.0',
      sdk_name: 'openctem-sdk-go',
      sdk_version: 'v0.9.0',
      sdk_status: 'current',
      sensor_product: 'openctemio-sensor',
      sensor_commit: 'abc1234',
      sensor_build_time: '2026-09-30T10:00:00Z',
    })
    // Two lines: the sensor release on top, the SDK under it.
    expect(c.querySelector('[data-slot="sensor-version"]')?.textContent).toBe('v0.5.0')
    expect(c.querySelector('[data-slot="sdk-version"]')?.textContent).toBe('SDK v0.9.0')
    expect(c.firstElementChild?.className).toContain('flex-col')
    const tip = c.querySelector('[title*="Product"]')
    expect(tip?.getAttribute('title')).toContain('Product: openctemio-sensor')
    expect(tip?.getAttribute('title')).toContain('Commit: abc1234')
    expect(tip?.getAttribute('title')).toContain('Built: ')
    expect(tip?.getAttribute('title')).toContain('SDK: openctem-sdk-go v0.9.0')
    // A current SDK carries no SDK tag.
    expect(screen.queryByText(/SDK (outdated|advisory)/)).toBeNull()
    expect(screen.getByText('latest')).toBeInTheDocument()
  })

  it('leaves out the parts that are not reported', () => {
    expect(cell({ version: 'v0.4.2' }).textContent).toContain('v0.4.2')
    expect(cell({ version: 'v0.4.2' }).textContent).not.toContain('SDK')
    expect(cell({ sdk_version: '0.9.0', sdk_status: 'current' }).textContent).toBe('SDK v0.9.0')
    expect(cell({ version: '', sdk_version: '' }).textContent).toBe('Not reported')
  })

  it('shows an outdated SDK as information and an SDK advisory as a warning', () => {
    cell({ version: 'v0.5.0', sdk_version: 'v0.8.0', sdk_status: 'outdated' })
    const outdated = screen.getByText('SDK outdated')
    expect(outdated.className).toContain('text-info')
    expect(outdated).toHaveAttribute('title', 'SDK v0.9.0 is available')

    cell({ version: 'v0.5.0', sdk_version: 'v0.6.0', sdk_status: 'advisory' })
    const advisory = screen.getByText('SDK advisory')
    expect(advisory.className).toContain('text-warning')
    expect(advisory).toHaveAttribute('title', 'This SDK release has a published security advisory')
  })

  it("judges each sensor against its own product's release line", () => {
    // v0.1.5 is far below the scanning sensor's minimum (v0.4.0), but the
    // connector's own line is v0.1.0..v0.2.0: an update, not unsupported.
    cell({ version: 'v0.1.5', sensor_product: 'openctemio-connector-tenable' })
    const update = screen.getByText('update')
    expect(update).toHaveAttribute('title', 'v0.2.0 is available')
    expect(screen.queryByText('unsupported')).toBeNull()
  })

  it('prefers the release line the API sent for the sensor', () => {
    cell({
      version: 'v0.1.0',
      product: 'openctemio-connector-tenable',
      product_known: true,
      product_latest_version: 'v0.3.0',
      product_min_version: 'v0.2.0',
    })
    expect(screen.getByText('unsupported')).toHaveAttribute(
      'title',
      'Older than the minimum supported v0.2.0'
    )
  })

  it('gives a custom product no update or unsupported verdict', () => {
    const c = cell({ version: 'v0.0.1', product: 'acme-custom', product_known: false })
    expect(c.textContent).toBe('v0.0.1')
    const c2 = cell({ version: 'v0.0.1', sensor_product: 'acme-custom' })
    expect(c2.textContent).toBe('v0.0.1')
  })
})

describe('sdkVersionOptions', () => {
  it('lists the stats versions newest first, "unknown" last, and keeps a stale selection', () => {
    expect(
      sdkVersionOptions({ unknown: 1, 'v0.8.1': 2, 'v0.9.0': 3 }, ['v0.7.0']).map((o) => [
        o.value,
        o.count,
      ])
    ).toEqual([
      ['v0.9.0', 3],
      ['v0.8.1', 2],
      ['v0.7.0', null],
      ['unknown', 1],
    ])
    expect(sdkVersionOptions(undefined)).toEqual([])
  })
})
