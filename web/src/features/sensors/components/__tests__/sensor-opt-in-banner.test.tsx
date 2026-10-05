import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import type { SensorOptInImpact } from '@/lib/api/sensor-opt-in-hooks'

const impact: { data?: SensorOptInImpact } = {}
vi.mock('@/lib/api/sensor-opt-in-hooks', async (orig) => {
  const actual = await orig<typeof import('@/lib/api/sensor-opt-in-hooks')>()
  return { ...actual, useSensorOptInImpact: () => impact }
})

import { affectedScans } from '@/lib/api/sensor-opt-in-hooks'

import { SensorOptInBanner } from '../sensor-opt-in-banner'

const scans = [
  {
    id: 's1',
    name: 'OAST sweep',
    status: 'active',
    uses_interactsh: true,
    uses_custom_templates: false,
  },
  {
    id: 's2',
    name: 'Custom checks',
    status: 'active',
    uses_interactsh: false,
    uses_custom_templates: true,
  },
]

describe('sensor opt-ins banner', () => {
  it('names the scans that ask for a switch that is off', () => {
    impact.data = {
      opt_ins: { allow_interactsh: false, allow_custom_templates: false },
      scans,
      truncated: false,
    }
    render(<SensorOptInBanner />)
    expect(screen.getByTestId('sensor-opt-in-banner')).toBeInTheDocument()
    expect(screen.getByText('OAST sweep')).toHaveAttribute('href', '/scans/s1')
    expect(screen.getByText('Custom checks')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Settings/ })).toHaveAttribute(
      'href',
      '/settings/authentication'
    )
  })

  it('leaves out scans whose switch is on, and hides when nothing is affected', () => {
    const data = {
      opt_ins: { allow_interactsh: true, allow_custom_templates: false },
      scans,
      truncated: false,
    }
    expect(affectedScans(data).map((s) => s.id)).toEqual(['s2'])
    impact.data = { ...data, opt_ins: { allow_interactsh: true, allow_custom_templates: true } }
    const { container } = render(<SensorOptInBanner />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing before the data arrives', () => {
    impact.data = undefined
    const { container } = render(<SensorOptInBanner />)
    expect(container).toBeEmptyDOMElement()
  })
})
