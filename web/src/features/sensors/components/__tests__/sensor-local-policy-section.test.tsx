import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { SensorLocalPolicySection } from '../sensor-local-policy-section'

describe('SensorLocalPolicySection', () => {
  it('renders nothing on an API without the report', () => {
    const { container } = render(<SensorLocalPolicySection sensor={{}} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows an enforced policy with its digest and summary, never ranges', () => {
    render(
      <SensorLocalPolicySection
        sensor={{
          local_policy: {
            state: 'enforced',
            source: 'file',
            digest: 'sha256:' + 'ab'.repeat(32),
            kill_switch: false,
            summary: {
              targets_allow: 2,
              targets_deny: 1,
              allow_private: true,
              ports: '443',
              allow_custom_templates: false,
              allow_interactsh: false,
            },
          },
        }}
      />
    )
    expect(screen.getByText('Enforced')).toBeInTheDocument()
    // The full digest, selectable, so it can be compared on the host.
    expect(screen.getByTestId('local-policy-digest')).toHaveTextContent('sha256:' + 'ab'.repeat(32))
    expect(screen.queryByTestId('no-policy-guidance')).not.toBeInTheDocument()
    expect(screen.getByText('Targets: 2 allowed, 1 denied')).toBeInTheDocument()
    expect(screen.getByText('Interactsh callbacks: refused')).toBeInTheDocument()
  })

  it('warns when the kill switch is engaged or no policy is installed', () => {
    const { rerender } = render(
      <SensorLocalPolicySection sensor={{ local_policy: { state: 'paused', kill_switch: true } }} />
    )
    expect(screen.getByText('Paused by the local kill switch')).toBeInTheDocument()
    rerender(
      <SensorLocalPolicySection
        sensor={{ local_policy: { state: 'absent', kill_switch: false } }}
      />
    )
    expect(screen.getByText('No local policy')).toBeInTheDocument()
    // The corrected guidance next to the sensor's warning (research/25 §2.2).
    const guidance = screen.getByTestId('no-policy-guidance')
    expect(guidance).toHaveTextContent('SENSOR_TEMPLATE_SIGNING_KEYS')
    expect(guidance).toHaveTextContent('your organization allows interactsh')
  })

  it('adds the guidance when the sensor repeats the absent-policy warning', () => {
    render(
      <SensorLocalPolicySection
        sensor={{
          local_policy: {
            state: 'enforced',
            kill_switch: false,
            warnings: ['no local policy: custom templates ... are allowed'],
          },
        }}
      />
    )
    expect(screen.getByTestId('no-policy-guidance')).toBeInTheDocument()
  })
})
