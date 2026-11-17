import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import * as defaults from './chart-defaults'

const SRC = join(__dirname, '../..')
const read = (rel: string) => readFileSync(join(SRC, rel), 'utf8')

/** Every colour inside a value, however deep. */
function colours(value: unknown): string[] {
  if (typeof value === 'string') return [value]
  if (value && typeof value === 'object') return Object.values(value).flatMap(colours)
  return []
}

describe('chart defaults', () => {
  it('take every colour from a theme token, so charts follow light and dark', () => {
    const all = Object.values(defaults).flatMap(colours)
    const raw = all.filter((v) => /#[0-9a-f]{3,8}\b|rgb\(|hsl\(|oklch\(/i.test(v))
    expect(raw).toEqual([])
    expect(all.some((v) => v.includes('var(--'))).toBe(true)
  })

  it('an axis shows labels only', () => {
    expect(defaults.CHART_AXIS).toMatchObject({ axisLine: false, tickLine: false })
    expect(defaults.CHART_AXIS.tick.fontSize).toBeGreaterThanOrEqual(12)
    expect(defaults.CHART_GRID.vertical).toBe(false)
  })

  it('the charts in the app spread the defaults and write no axis or grid colours of their own', () => {
    for (const file of [
      'components/dashboard-kit/series-viz.tsx',
      'features/dashboard/components/program-health-view.tsx',
    ]) {
      const text = read(file)
      expect(text, file).toContain('CHART_AXIS')
      expect(text, file).not.toMatch(/<(XAxis|YAxis)[^>]*tick=\{\{/s)
      expect(text, file).not.toMatch(/<CartesianGrid[^>]*stroke=/s)
    }
  })
})
