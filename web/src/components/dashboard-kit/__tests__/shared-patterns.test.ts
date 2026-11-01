import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * One shared component per pattern in the dashboard kit: a part-to-whole bar
 * is StackedBar, a ranked bar list is RankedBars, a stage state is
 * StageStateIcon. A widget that draws its own copy fails here; extend the
 * shared component instead.
 */
const DIR = path.join(__dirname, '..')
const files = fs
  .readdirSync(DIR)
  .filter((f) => f.endsWith('.tsx'))
  .map((f) => ({ f, src: fs.readFileSync(path.join(DIR, f), 'utf8') }))

describe('dashboard kit shared patterns', () => {
  it('draws part-to-whole bars only with StackedBar', () => {
    const own = files
      .filter(({ f }) => f !== 'stacked-bar.tsx')
      .filter(({ src }) => /style=\{\{\s*flex:/.test(src))
      .map(({ f }) => f)
    expect(own).toEqual([])
  })

  it('sorts and draws ranked bar lists only with RankedBars', () => {
    const own = files
      .filter(({ f }) => f !== 'ranked-bars.tsx')
      .filter(({ src }) => /data-testid="ranked-bar"|\.sort\([^)]*b\.value - a\.value/.test(src))
      .map(({ f }) => f)
    expect(own).toEqual([])
  })

  it('shows a stage state only with the shared icon set', () => {
    const own = files
      .filter(({ f }) => f !== 'stage-state.tsx')
      .filter(
        ({ src }) =>
          /\bStageState\b/.test(src) &&
          /from 'lucide-react'/.test(src) &&
          /\b(XCircle|CheckCircle2|TriangleAlert|Check|X|Minus)\b/.test(src)
      )
      .map(({ f }) => f)
    expect(own).toEqual([])
  })
})
