import { afterEach, describe, expect, it, vi } from 'vitest'
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

  it('shows allow_all as everything the platform signs, and tolerates a missing mode', () => {
    const summary = {
      targets_allow: 1,
      targets_deny: 0,
      allow_private: true,
      allow_custom_templates: false,
      allow_interactsh: false,
    }
    const { rerender } = render(
      <SensorLocalPolicySection
        sensor={{
          local_policy: {
            state: 'enforced',
            kill_switch: false,
            summary: { ...summary, mode: 'allow_all' },
          },
        }}
      />
    )
    expect(screen.getByText('Targets: allows everything the platform signs')).toBeInTheDocument()
    expect(screen.queryByText(/1 allowed/)).not.toBeInTheDocument()
    rerender(
      <SensorLocalPolicySection
        sensor={{ local_policy: { state: 'enforced', kill_switch: false, summary } }}
      />
    )
    expect(screen.getByText('Targets: 1 allowed, 0 denied')).toBeInTheDocument()
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

  describe('suggested policy', () => {
    afterEach(() => vi.unstubAllGlobals())

    const policy =
      'apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow:\n    - "10.20.0.0/16"\n'

    it('offers the suggested policy as one host command when none is installed', async () => {
      const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ policy }) })
      vi.stubGlobal('fetch', fetchMock)
      render(
        <SensorLocalPolicySection
          sensor={{
            id: 's-1',
            local_policy: { state: 'absent', required: true, kill_switch: false },
          }}
        />
      )
      expect(screen.getByText('Network scans refused: no local policy')).toBeInTheDocument()
      const block = await screen.findByTestId('policy-suggestion')
      const pre = block.querySelector('pre')
      expect(pre?.textContent).toContain(
        "sudo tee /etc/openctem/sensor-policy.yaml >/dev/null <<'OPENCTEM_POLICY'"
      )
      expect(pre?.textContent).toContain('    - "10.20.0.0/16"\nOPENCTEM_POLICY')
      // The sensor's own config templates route, never a key in the URL.
      expect(String(fetchMock.mock.calls[0][0])).toMatch(/\/sensors\/s-1\/config-templates$/)
      // A sensor that refuses network jobs gets the suggestion, not the
      // custom-template guidance.
      expect(screen.queryByTestId('no-policy-guidance')).not.toBeInTheDocument()
    })

    it('shows no suggestion once a policy is enforced', () => {
      const fetchMock = vi.fn()
      vi.stubGlobal('fetch', fetchMock)
      render(
        <SensorLocalPolicySection
          sensor={{ id: 's-1', local_policy: { state: 'enforced', kill_switch: false } }}
        />
      )
      expect(screen.queryByTestId('policy-suggestion')).not.toBeInTheDocument()
      expect(fetchMock).not.toHaveBeenCalled()
    })
  })
})
