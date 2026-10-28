/**
 * Gate: AI output is always labelled with the one shared AI badge (API docs:
 * architecture/ai-analysis.md, "Labelling").
 *
 * - Every component that renders an AI actor (the activity feed rows, the
 *   approval proposal badge, the legacy triage result) renders the shared
 *   `AIBadge`.
 * - No second AI badge: the shared component is the only place the "AI analyst",
 *   "Suggested by AI" and "Proposed by AI" labels are written.
 */
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SRC = join(__dirname, '..', '..', '..', '..')
const SHARED_BADGE = "from '@/features/shared/components/ai-badge'"

const RENDER_AI_ACTORS = [
  'features/activity/components/activity-items.tsx',
  'features/findings/components/ai-proposal-badge.tsx',
  'features/ai-triage/components/triage-result-card.tsx',
]

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) {
      if (name === '__tests__' || name === 'node_modules') continue
      walk(p, out)
    } else if (/\.(tsx?|jsx?)$/.test(name) && !/\.test\./.test(name)) {
      out.push(p)
    }
  }
  return out
}

describe('AI badge gate', () => {
  it('every component that renders an AI actor uses the shared AI badge', () => {
    const missing = RENDER_AI_ACTORS.filter((f) => {
      const src = readFileSync(join(SRC, f), 'utf8')
      return !(src.includes(SHARED_BADGE) && /<AIBadge\b/.test(src))
    })
    expect(missing).toEqual([])
  })

  it('only the shared badge writes the AI badge labels', () => {
    const labels = /['"`](Suggested|Proposed) by AI\b/
    const offenders = walk(SRC).filter((f) => {
      if (f.includes(join('lib', 'i18n'))) return false
      if (f.endsWith(join('shared', 'components', 'ai-badge.tsx'))) return false
      return labels.test(readFileSync(f, 'utf8'))
    })
    expect(offenders.map((f) => relative(SRC, f))).toEqual([])
  }, 60_000)
})
