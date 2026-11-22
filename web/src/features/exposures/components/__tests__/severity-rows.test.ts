import { describe, expect, it } from 'vitest'
import { severityRows } from '../exposure-type-overview'

describe('severityRows', () => {
  it('names each severity with the label it is given (the console language), in severity order', () => {
    const rows = severityRows({ low: 1, critical: 2, medium: 3 }, (s) => `vi:${s}`)
    expect(rows.map((r) => r.name)).toEqual(['vi:critical', 'vi:medium', 'vi:low'])
    expect(rows.map((r) => r.value)).toEqual([2, 3, 1])
  })
})
