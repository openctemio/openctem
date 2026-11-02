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
    expect(screen.getByText('Narrowed by host policy (3 rules)')).toBeInTheDocument()
    expect(screen.queryByTestId('policy-allows-nothing')).not.toBeInTheDocument()
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
    expect(screen.getAllByText('Follows platform scope').length).toBeGreaterThan(0)
    expect(screen.queryByTestId('policy-allows-nothing')).not.toBeInTheDocument()
    // The corrected guidance next to the sensor's warning (research/25 §2.2).
    const guidance = screen.getByTestId('no-policy-guidance')
    expect(guidance).toHaveTextContent('SENSOR_TEMPLATE_SIGNING_KEYS')
    expect(guidance).toHaveTextContent('your organization allows interactsh')
  })

  it('says a newly paired sensor with an empty allow list allows nothing, and where to edit it', () => {
    render(
      <SensorLocalPolicySection
        sensor={{
          name: 'office-1',
          local_policy: {
            state: 'enforced',
            source: 'file',
            kill_switch: false,
            summary: {
              targets_allow: 0,
              targets_deny: 0,
              allow_private: false,
              allow_custom_templates: false,
              allow_interactsh: false,
            },
          },
        }}
      />
    )
    expect(screen.getAllByText('Allows nothing yet').length).toBeGreaterThan(0)
    expect(screen.getByTestId('policy-allows-nothing')).toHaveTextContent(
      'platform sends it no scan'
    )
    const help = screen.getByTestId('policy-file-help')
    expect(help).toHaveTextContent('sensors/office-1/policy/sensor-policy.yaml')
    expect(help).toHaveTextContent('docker compose restart office-1')
    expect(help).toHaveTextContent('/etc/openctem/sensor-policy.yaml')
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
      expect(screen.getByText('Allows nothing yet: list what it may scan')).toBeInTheDocument()
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
