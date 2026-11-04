import path from 'path'
import type { Page } from '@playwright/test'

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')

interface AxeResult {
  violations: Array<{ id: string; nodes: Array<{ target: string[] }> }>
}

/**
 * Runs the named axe-core rules on the whole page (shell included) and
 * returns one line per violation: "rule: selector, selector".
 */
export async function axeRuleViolations(page: Page, rules: string[]): Promise<string[]> {
  await page.addScriptTag({ path: AXE })
  const result = (await page.evaluate(async (only) => {
    const w = window as unknown as {
      axe: { run: (ctx: unknown, opts: unknown) => Promise<AxeResult> }
    }
    return w.axe.run(document, { runOnly: { type: 'rule', values: only } })
  }, rules)) as AxeResult
  return result.violations.map(
    (v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`
  )
}

const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

/**
 * Critical and serious axe violations on the WHOLE page (shell included) under
 * WCAG 2.2 AA, one line per violation: "rule (impact): selector, selector".
 * seriousAxe (helpers/layout.ts) checks the main content only.
 */
export async function wcagViolations(page: Page): Promise<string[]> {
  await page.addScriptTag({ path: AXE })
  const result = (await page.evaluate(async (tags) => {
    const w = window as unknown as {
      axe: { run: (ctx: unknown, opts: unknown) => Promise<unknown> }
    }
    return w.axe.run(document, {
      runOnly: { type: 'tag', values: tags },
      resultTypes: ['violations'],
    })
  }, WCAG_TAGS)) as {
    violations: Array<{ id: string; impact: string | null; nodes: Array<{ target: string[] }> }>
  }
  return result.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
}
