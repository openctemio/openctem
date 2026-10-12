import { describe, expect, it } from 'vitest'

import { localPolicySummaryLines, localPolicyView, shortPolicyDigest } from '../local-policy'

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
