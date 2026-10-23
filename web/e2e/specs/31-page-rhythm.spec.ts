import { test, expect } from '../fixtures/authenticated-page'

/**
 * Page rhythm (research/244). On every page migrated to `PageStack`, the gaps
 * between the page's blocks are the spacing tokens, whatever optional block
 * (a banner) renders or not:
 *
 * - page header to its tab strip: 16px (`--spacing-page-tight`);
 * - tab strip to the next block: 20px (`--spacing-page`);
 * - between any two other blocks of the stack: 20px.
 *
 * It also checks the metric strip rules where a page has one: at most five
 * tiles, every tile a link or a filter toggle, two columns and no sideways
 * scroll on a phone. Screenshots of each page and width are attached.
 *
 * The bug this guards: /scans/runs drew its metric strip flush against the tab
 * underline because the 20px lived on a banner that renders nothing.
 *
 * A migrated page joins ROUTES in the pull request that migrates it.
 */
const ROUTES = ['/scans', '/scans/runs', '/scans/workflows', '/scans/approvals']

const PAGE_GAP = 20
const TIGHT_GAP = 16
const WIDTHS = [1440, 390]

type Rhythm = {
  stack: boolean
  pairs: { from: string; to: string; gap: number }[]
  strip: { tiles: number; interactive: number; overflowX: boolean; columns: number } | null
}

for (const route of ROUTES) {
  for (const width of WIDTHS) {
    test(`page rhythm on ${route} at ${width}px`, async ({ page }, info) => {
      await page.setViewportSize({ width, height: width < 600 ? 844 : 900 })
      await page.goto(route)
      const stack = page.locator('[data-slot="page-stack"]').first()
      await expect(stack).toBeVisible({ timeout: 45_000 })
      await page.waitForLoadState('networkidle')
      await info.attach(`${route}-${width}`, {
        body: await page.screenshot(),
        contentType: 'image/png',
      })

      const r: Rhythm = await stack.evaluate((root) => {
        const name = (el: Element) => el.getAttribute('data-slot') || el.tagName.toLowerCase()
        // Blocks are the stack's visible children; nested stacks are flattened
        // so a tab panel's blocks count as page blocks.
        const blocks: Element[] = []
        const walk = (el: Element) => {
          for (const c of Array.from(el.children)) {
            const box = c.getBoundingClientRect()
            const cs = getComputedStyle(c)
            if (cs.position === 'fixed' || cs.position === 'absolute') continue
            if (box.height === 0 && box.width === 0) continue
            if (c.getAttribute('data-slot') === 'page-stack') walk(c)
            else blocks.push(c)
          }
        }
        walk(root)
        const pairs = []
        for (let i = 1; i < blocks.length; i++) {
          const a = blocks[i - 1].getBoundingClientRect()
          const b = blocks[i].getBoundingClientRect()
          pairs.push({
            from: name(blocks[i - 1]),
            to: name(blocks[i]),
            gap: Math.round(b.top - a.bottom),
          })
        }
        const dl = root.querySelector('[data-slot="metric-strip"]') as HTMLElement | null
        let strip = null
        if (dl) {
          const tiles = Array.from(dl.children)
          strip = {
            tiles: tiles.length,
            interactive: tiles.filter((t) => t.matches('a[href], button')).length,
            overflowX: dl.scrollWidth > dl.clientWidth + 1,
            columns: getComputedStyle(dl).gridTemplateColumns.split(' ').length,
          }
        }
        return { stack: true, pairs, strip }
      })

      expect(r.pairs.length, 'the page has at least a header and one block').toBeGreaterThan(0)
      for (const p of r.pairs) {
        const want = p.from === 'page-header' && p.to === 'page-tabs' ? TIGHT_GAP : PAGE_GAP
        expect(
          Math.abs(p.gap - want),
          `${p.from} -> ${p.to} gap is ${p.gap}px, want ${want}px`
        ).toBeLessThanOrEqual(1)
      }
      const tabs = r.pairs.find((p) => p.from === 'page-tabs')
      if (tabs) expect(Math.abs(tabs.gap - PAGE_GAP)).toBeLessThanOrEqual(1)

      if (r.strip) {
        expect(r.strip.tiles, 'at most five tiles').toBeLessThanOrEqual(5)
        expect(r.strip.interactive, 'every tile is a link or a filter toggle').toBe(r.strip.tiles)
        expect(r.strip.overflowX, 'the strip never scrolls sideways').toBe(false)
        if (width < 640) expect(r.strip.columns, 'two columns on a phone').toBe(2)
      }

      const pageOverflow = await page.evaluate(
        () => document.documentElement.scrollWidth > window.innerWidth + 1
      )
      expect(pageOverflow, 'no horizontal page scroll').toBe(false)
    })
  }
}
