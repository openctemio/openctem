import { describe, it, expect } from 'vitest'
import { retestActivity } from '../retest-activity'
import { isRetestable } from '../../api/use-finding-retests'

describe('retestActivity', () => {
  it('ignores other activity types', () => {
    expect(retestActivity('status_changed', {})).toBeNull()
  })

  it('renders a request', () => {
    expect(retestActivity('retest_requested', { template_id: 'tpl', trigger: 'auto' })).toEqual({
      type: 'verified',
      content: 'Auto-retest started (template tpl)',
    })
  })

  it('renders a completion that moved the finding as a status change', () => {
    const r = retestActivity('retest_completed', {
      moved: true,
      outcome: 'still_present',
      regression: true,
      template_id: 'tpl',
    })
    expect(r?.type).toBe('status_changed')
    expect(r?.content).toBe('Retest: Still present (regression) (template tpl)')
  })

  it('renders an unknown outcome with its reason, as a single line', () => {
    const r = retestActivity('retest_completed', {
      moved: false,
      outcome: 'unknown',
      reason: 'target unreachable: connection refused',
    })
    expect(r).toEqual({
      type: 'verified',
      content: 'Retest: Unknown — target unreachable: connection refused',
    })
  })
})

describe('isRetestable', () => {
  it('needs a nuclei template and a retestable status', () => {
    expect(isRetestable({ toolName: 'nuclei', ruleId: 'tpl', status: 'resolved' })).toBe(true)
    expect(isRetestable({ toolName: 'Nuclei', ruleId: 'tpl', status: 'fix_applied' })).toBe(true)
    expect(isRetestable({ toolName: 'nuclei', ruleId: '', status: 'confirmed' })).toBe(false)
    expect(isRetestable({ toolName: 'trivy', ruleId: 'CVE-1', status: 'confirmed' })).toBe(false)
    expect(isRetestable({ toolName: 'nuclei', ruleId: 'tpl', status: 'false_positive' })).toBe(
      false
    )
  })
})
