import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { mergeShownMapping } from '../ticketing-mapping'

describe('mergeShownMapping', () => {
  it('a cleared field removes its key (set -> clear -> reload shows cleared)', () => {
    const stored = { critical: 'Highest', high: 'High' }
    expect(mergeShownMapping(stored, { critical: '', high: 'High', medium: '', low: '' })).toEqual({
      high: 'High',
    })
  })

  it('keeps keys the dialog does not show', () => {
    expect(mergeShownMapping({ wont_fix: 'Closed' }, { resolved: 'Done' })).toEqual({
      wont_fix: 'Closed',
      resolved: 'Done',
    })
  })

  it('trims values', () => {
    expect(mergeShownMapping(undefined, { high: '  High ' })).toEqual({ high: 'High' })
  })
})

describe('ticketing configure dialog', () => {
  it('saves the shown mapping fields through mergeShownMapping (no blank pruning)', () => {
    const src = readFileSync(
      join(process.cwd(), 'src/app/(dashboard)/settings/integrations/ticketing/page.tsx'),
      'utf8'
    )
    expect(src).toMatch(/severity_to_priority:\s*mergeShownMapping\(/)
    expect(src).toMatch(/status_outbound:\s*mergeShownMapping\(/)
    expect(src).not.toMatch(/const pruned = /)
  })
})
