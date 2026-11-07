import { describe, expect, it } from 'vitest'
import { enTranslate as t } from '../translate'
import { ranWithLines, ranWithSeverityLine, severityText } from '../ran-with'

describe('severityText', () => {
  it('collapses a contiguous run to a range', () => {
    expect(severityText(['low', 'medium', 'high', 'critical'])).toBe('low..critical')
    expect(severityText(['critical', 'high'])).toBe('high..critical')
  })
  it('lists a gap or a single value', () => {
    expect(severityText(['low', 'critical'])).toBe('low, critical')
    expect(severityText(['info'])).toBe('info')
    expect(severityText('high')).toBe('high')
  })
  it('ignores junk', () => {
    expect(severityText(undefined)).toBe('')
    expect(severityText([1, {}])).toBe('')
  })
})

describe('ranWithLines', () => {
  it('names the layer that set each value', () => {
    const lines = ranWithLines(
      {
        severity: { value: ['low', 'medium', 'high', 'critical'], source: 'depth_overlay' },
        tags: { value: ['cve'], source: 'template_step' },
        exclude_tags: { value: ['dos'], source: 'stage_fixed' },
      },
      t
    )
    expect(lines).toEqual([
      'Severity low..critical (depth default)',
      'Tags cve (workflow step)',
      'Excluded tags dos (fixed by the stage)',
    ])
  })
  it('is empty without data and drops an unknown source label', () => {
    expect(ranWithLines(undefined, t)).toEqual([])
    expect(ranWithSeverityLine({ severity: { value: ['high'], source: 'weird' } }, t)).toBe(
      'Severity high'
    )
  })
})
