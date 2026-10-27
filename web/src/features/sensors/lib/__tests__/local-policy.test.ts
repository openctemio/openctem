import { describe, expect, it } from 'vitest'

import {
  localPolicySummaryLines,
  localPolicyView,
  policyApplyCommand,
  shortPolicyDigest,
} from '../local-policy'

describe('localPolicyView', () => {
  it('maps every state', () => {
    expect(localPolicyView({ state: 'enforced', kill_switch: false }).tone).toBe('ok')
    expect(localPolicyView({ state: 'paused', kill_switch: true }).label).toBe(
      'Paused (kill switch)'
    )
    expect(localPolicyView({ state: 'absent', kill_switch: false }).tone).toBe('warn')
    expect(localPolicyView({ state: 'unknown', kill_switch: false }).label).toBe('Not reported')
    expect(localPolicyView(undefined).tone).toBe('muted')
  })
})

describe('shortPolicyDigest', () => {
  it('drops the algorithm and shortens', () => {
    expect(shortPolicyDigest('sha256:' + 'ab'.repeat(32))).toBe('abababababab')
    expect(shortPolicyDigest('')).toBe('')
  })
})

describe('localPolicySummaryLines', () => {
  it('describes the shape, never ranges', () => {
    const lines = localPolicySummaryLines({
      state: 'enforced',
      kill_switch: false,
      summary: {
        targets_allow: 2,
        targets_deny: 1,
        allow_private: true,
        ports: '443',
        tools: ['nuclei'],
        checks: [],
        allow_custom_templates: false,
        allow_interactsh: false,
        max_rps: 50,
      },
    })
    expect(lines).toContain('Targets: 2 allowed, 1 denied')
    expect(lines).toContain('Job types: none')
    expect(lines).toContain('Rate: at most 50 requests/s')
    expect(
      localPolicySummaryLines({
        state: 'enforced',
        kill_switch: false,
        summary: {
          targets_allow: -1,
          targets_deny: 0,
          allow_private: false,
          allow_custom_templates: false,
          allow_interactsh: false,
        },
      })[0]
    ).toBe('Targets: any outside 0 denied entries')
    expect(localPolicySummaryLines({ state: 'absent', kill_switch: false })).toEqual([])
  })
})

describe('policyApplyCommand', () => {
  it('writes the reviewed policy to the default path with a quoted heredoc', () => {
    const cmd = policyApplyCommand('apiVersion: openctem.io/sensor-policy/v1\ntargets: {}')
    expect(cmd.split('\n')).toEqual([
      'sudo install -d -m 0755 /etc/openctem',
      "sudo tee /etc/openctem/sensor-policy.yaml >/dev/null <<'OPENCTEM_POLICY'",
      'apiVersion: openctem.io/sensor-policy/v1',
      'targets: {}',
      'OPENCTEM_POLICY',
      'sudo chmod 0644 /etc/openctem/sensor-policy.yaml',
      '',
    ])
    // A trailing newline in the policy is not doubled.
    expect(policyApplyCommand('a: 1\n')).toContain('a: 1\nOPENCTEM_POLICY')
  })
})
