import { describe, expect, it } from 'vitest'
import { defaultT } from '@/features/assets/lib/default-t'
import { stepHref, stepRoleLabel, storyIsEmpty, storyUrl, type Story } from '../story'

describe('story helpers', () => {
  it('builds the subject URL', () => {
    expect(storyUrl('finding', 'f1')).toBe('/api/v1/findings/f1/story')
    expect(storyUrl('asset', 'a/1')).toBe('/api/v1/assets/a%2F1/story')
  })

  it('links visible steps to their record and never a hidden one', () => {
    expect(stepHref({ kind: 'asset', hidden: false, asset: { id: 'a1', name: 'x' } })).toBe(
      '/assets/a1'
    )
    expect(stepHref({ kind: 'asset', hidden: false, asset: { id: 'a1', subject: true } })).toBe(
      undefined
    )
    expect(
      stepHref({ kind: 'scan', hidden: false, scan: { role: 'reported', run_id: 'r 1' } })
    ).toBe('/scans/runs?run=r%201')
    expect(
      stepHref({ kind: 'asset', hidden: true, asset: { id: 'leak', via: 'parent' } })
    ).toBeUndefined()
  })

  it('names what each step did', () => {
    expect(
      stepRoleLabel(defaultT, {
        kind: 'scan',
        hidden: false,
        scan: { role: 'discovered', run_id: 'r' },
      })
    ).toBe('Discovered by')
    expect(stepRoleLabel(defaultT, { kind: 'report', hidden: false })).toBe('Reported by')
    expect(stepRoleLabel(defaultT, { kind: 'scan', hidden: true })).toBe('A step you cannot see')
  })

  it('treats a story with only its subject as empty', () => {
    const base: Story = {
      subject: { kind: 'finding', id: 'f1' },
      steps: [{ kind: 'finding', hidden: false, finding: { id: 'f1', title: 't' } }],
      hidden: 0,
      truncated: false,
      more_reports: 0,
      max_steps: 16,
    }
    expect(storyIsEmpty(base)).toBe(true)
    expect(storyIsEmpty({ ...base, steps: [{ kind: 'asset', hidden: true }, ...base.steps] })).toBe(
      false
    )
  })
})
