/**
 * Gate: AI output is always labelled with the one shared AI badge and always
 * rendered as plain text (API docs: architecture/ai-analysis.md, "Labelling").
 *
 * - Every component under `features/ai-suggestions/components` either renders
 *   the shared `AIBadge` itself or renders AI content only through
 *   `AISuggestionCard` (which does).
 * - No file in the AI suggestion feature renders markup or markdown
 *   (`dangerouslySetInnerHTML`, the markdown preview or editor).
 * - No second AI badge: the shared component is the only place the "Suggested
 *   by AI" / "Proposed by AI" labels are written.
 *
 * The card's render test (`ai-suggestion-card.test.tsx`) proves the badge is
 * actually on screen.
 */
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SRC = join(__dirname, '..', '..', '..')
const FEATURE = join(__dirname, '..')
const COMPONENTS = join(FEATURE, 'components')

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) {
      if (name === '__tests__' || name === 'node_modules') continue
      walk(p, out)
    } else if (/\.(tsx?|jsx?)$/.test(name)) {
      out.push(p)
    }
  }
  return out
}

const SHARED_BADGE = "from '@/features/shared/components/ai-badge'"
const CARD = "from './ai-suggestion-card'"

describe('AI badge gate', () => {
  it('every AI suggestion component renders the shared AI badge or the card that does', () => {
    const files = walk(COMPONENTS).filter((f) => f.endsWith('.tsx'))
    expect(files.length).toBeGreaterThan(0)
    const missing = files.filter((f) => {
      const src = readFileSync(f, 'utf8')
      const usesBadge = src.includes(SHARED_BADGE) && /<AIBadge\b/.test(src)
      const usesCard = src.includes(CARD) && /<AISuggestionCard\b/.test(src)
      return !usesBadge && !usesCard
    })
    expect(missing.map((f) => relative(SRC, f))).toEqual([])
  })

  it('no AI suggestion file renders markup or markdown', () => {
    const offenders = walk(FEATURE).filter((f) =>
      /dangerouslySetInnerHTML|MarkdownPreview|markdown-editor|react-markdown|MDEditor/.test(
        readFileSync(f, 'utf8')
      )
    )
    expect(offenders.map((f) => relative(SRC, f))).toEqual([])
  })

  it('only the shared badge writes the AI badge labels', () => {
    const labels = /['"`](Suggested|Proposed) by AI\b/
    const offenders = walk(SRC).filter((f) => {
      if (f.includes(`${join('lib', 'i18n')}`)) return false
      if (f.endsWith(join('shared', 'components', 'ai-badge.tsx'))) return false
      return labels.test(readFileSync(f, 'utf8'))
    })
    expect(offenders.map((f) => relative(SRC, f))).toEqual([])
  }, 60_000)
})
