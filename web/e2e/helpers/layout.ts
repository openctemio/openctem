import path from 'path'
import type { Page } from '@playwright/test'

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')

/**
 * Controls drawn past the edge of their card (a clear button pushed out by a
 * full-width picker, a combobox wider than its column), and horizontal page
 * scroll. Both broke the pentest finding editor for findings with a CWE and an
 * OWASP category (research/269).
 */
export async function layoutDefects(page: Page) {
  return page.evaluate(() => {
    const out: string[] = []
    for (const el of Array.from(
      document.querySelectorAll('main button, main input, main [role=combobox]')
    )) {
      const card = el.closest('[data-slot=card]')
      const r = el.getBoundingClientRect()
      if (!card || r.width === 0) continue
      const c = card.getBoundingClientRect()
      if (r.right > c.right + 1 || r.left < c.left - 1) {
        out.push(el.getAttribute('aria-label') || el.textContent?.trim().slice(0, 40) || el.tagName)
      }
    }
    const doc = document.documentElement
    if (doc.scrollWidth > doc.clientWidth)
      out.push(`page scrolls sideways by ${doc.scrollWidth - doc.clientWidth}px`)
    return out
  })
}

/** Serious and critical axe violations inside the page's main content. */
export async function seriousAxe(page: Page) {
  await page.addScriptTag({ path: AXE })
  const result = await page.evaluate(async () => {
    const w = window as unknown as {
      axe: {
        run: (
          ctx: unknown,
          opts: unknown
        ) => Promise<{
          violations: Array<{
            id: string
            impact: string | null
            nodes: Array<{ target: string[] }>
          }>
        }>
      }
    }
    return w.axe.run({ include: [['main#content']] }, { resultTypes: ['violations'] })
  })
  return result.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
}
