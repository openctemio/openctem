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
      outcome: 'still_vulnerable',
      regression: true,
      template_id: 'tpl',
    })
    expect(r?.type).toBe('status_changed')
    expect(r?.content).toBe('Retest: Still vulnerable (regression) (template tpl)')
  })

  it('renders an inconclusive outcome with its reason, as a single line', () => {
    const r = retestActivity('retest_completed', {
      moved: false,
      outcome: 'inconclusive',
      reason: 'target unreachable: connection refused',
    })
    expect(r).toEqual({
      type: 'verified',
      content: 'Retest: Inconclusive — target unreachable: connection refused',
    })
  })

  it('never calls a bare non-match fixed, old entries included', () => {
    expect(retestActivity('retest_completed', { outcome: 'not_reproduced' })?.content).toBe(
      'Retest: Not reproduced (not confirmed)'
    )
    expect(retestActivity('retest_completed', { outcome: 'fixed' })?.content).toBe(
      'Retest: Fixed (unverified non-match)'
    )
    expect(retestActivity('retest_completed', { outcome: 'confirmed_fixed' })?.content).toBe(
      'Retest: Verified fixed'
    )
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

describe('evidence reveal activity', () => {
  it('says who revealed how many values and why, never the values', () => {
    const a = retestActivity('evidence_revealed', {
      placeholders: ['«secret:authorization#1»', '«secret:cookie#1»'],
      purpose: 'copy_curl',
    })
    expect(a).toEqual({
      type: 'evidence_added',
      content: 'Copied the reproduction curl with 2 masked evidence values',
    })
    expect(
      retestActivity('evidence_revealed', { placeholders: ['x'], purpose: 'view' })?.content
    ).toBe('Revealed 1 masked evidence value')
  })
})
