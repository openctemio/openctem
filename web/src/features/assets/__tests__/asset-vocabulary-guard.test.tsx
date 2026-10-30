import { describe, it, expect, vi } from 'vitest'
import { render } from '@testing-library/react'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { CriticalityBadge } from '../components/classification-badges'
import { RiskScoreBadge } from '@/features/shared/components/risk-score-badge'

/**
 * Asset vocabulary guard (research/271). Criticality (how much the asset
 * matters to the business) and the risk band share the words High, Medium,
 * Low and Critical. Every surface keeps them apart, and one term names the
 * per-asset findings count:
 *
 * - risk is drawn by RiskScoreBadge, which shows the number and names "Risk"
 *   in its tooltip and accessible name; a bare score SeverityBadge would
 *   bring back an unnamed "High";
 * - criticality always carries its noun in the tooltip and accessible name;
 * - the count is "N open findings" (OpenFindingsLink), never "issues found".
 */
vi.mock('@/context/risk-scoring-provider', () => ({
  useRiskThresholds: () => ({ critical_min: 80, high_min: 60, medium_min: 40, low_min: 20 }),
}))

const WEB = join(__dirname, '..', '..', '..', '..')
const SRC = join(WEB, 'src')

function walk(path: string, out: string[]) {
  const st = statSync(path)
  if (st.isDirectory()) {
    for (const name of readdirSync(path)) {
      if (name === 'node_modules' || name.startsWith('.') || name === 'generated') continue
      walk(join(path, name), out)
    }
  } else if (/\.(tsx?|json)$/.test(path) && !/\.test\.tsx?$/.test(path)) {
    out.push(path)
  }
}
const files: string[] = []
walk(SRC, files)
const rel = (abs: string) => relative(WEB, abs).split(sep).join('/')

describe('asset vocabulary guard', () => {
  it('draws a risk score only through RiskScoreBadge', () => {
    const offenders = files
      .filter((f) => f.endsWith('.tsx'))
      .filter((f) => !f.endsWith('features/shared/components/risk-score-badge.tsx'))
      .filter((f) => /<SeverityBadge\b[^>]*?\bscore=/.test(readFileSync(f, 'utf8')))
      .map(rel)
    expect(offenders).toEqual([])
  })

  it('never says "issues found" for an asset findings count', () => {
    const offenders = files
      .filter((f) => {
        const s = readFileSync(f, 'utf8')
        return /assets\.issues\.|issues? found/i.test(s) && !/pentestCampaigns/.test(rel(f))
      })
      .map(rel)
      // "No issues found" is the pentest link search's empty state, not a count.
      .filter((f) => !f.includes('campaign-links-section'))
    expect(offenders).toEqual([])
  })

  it('criticality and risk never read as the same word', () => {
    for (const [criticality, score] of [
      ['critical', 90],
      ['high', 70],
      ['medium', 50],
      ['low', 30],
    ] as const) {
      const crit = render(
        <CriticalityBadge criticality={criticality} showTooltip={false} />
      ).container
      const risk = render(<RiskScoreBadge score={score} />).container
      // Criticality names itself to assistive tech and in its tooltip.
      expect(crit.textContent).toMatch(/^Criticality: /)
      expect(crit.querySelector('[title^="Criticality: "]')).not.toBeNull()
      // Risk shows only the number; its band word is in the name and tooltip.
      expect(risk.textContent).toBe(String(score))
      expect(risk.querySelector('[aria-label^="Risk "]')).not.toBeNull()
    }
  })
})
