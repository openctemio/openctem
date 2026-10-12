import { describe, it, expect } from 'vitest'

import {
  formatLabel,
  importTotals,
  placeText,
  severityCounts,
  vexModeText,
} from '../import-results'

describe('import-results helpers', () => {
  it('labels formats and keeps unknown values', () => {
    expect(formatLabel('cyclonedx')).toBe('CycloneDX')
    expect(formatLabel('future')).toBe('future')
    expect(formatLabel(undefined)).toBe('Unknown format')
  })

  it('orders severities and drops zeros', () => {
    const file = {
      name: 'a',
      stats: { by_severity: { info: 1, critical: 2, low: 0 } },
    }
    expect(severityCounts(file as never)).toEqual([
      { severity: 'critical', count: 2 },
      { severity: 'info', count: 1 },
    ])
  })

  it('places a message at its line and column', () => {
    expect(placeText({ line: 4, column: 2, message: 'm' })).toBe('line 4, column 2: m')
    expect(placeText({ line: 4, message: 'm' })).toBe('line 4: m')
    expect(placeText({ message: 'm' })).toBe('m')
  })

  it('sums the files of an upload', () => {
    const t = importTotals([
      {
        name: 'a',
        stats: { findings: 2 },
        ingest: { findings_created: 2 },
        vex: { matched: 3, closed: 1 },
      },
      { name: 'b', error: { kind: 'malformed', message: 'x' } },
    ] as never)
    expect(t).toMatchObject({
      files: 2,
      failed: 1,
      findings: 2,
      created: 2,
      vexMatched: 3,
      vexClosed: 1,
    })
  })

  it('explains each VEX mode', () => {
    expect(vexModeText('enforce', true)).toMatch(/close/)
    expect(vexModeText('enforce', false)).toMatch(/approve permission/)
    expect(vexModeText('off', false)).toMatch(/stored/)
    expect(vexModeText('dry_run', false)).toMatch(/nothing is closed/)
  })
})
