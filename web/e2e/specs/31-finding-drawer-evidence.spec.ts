import path from 'path'
import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * The finding drawer shows what the scanner saw (research/276): for a web
 * finding, the request AND the response of the newest detection, with the
 * matched part marked and secret values masked. Seeded by web/e2e/ci/seed.sh
 * ("E2E evidence 01": an HTTP exchange, then the tool's curl item, the order
 * nuclei sends them in). Before the fix the drawer showed only the curl item,
 * which sorted first, so the response was never visible.
 *
 * Runs at 1440 and 390 wide, checks the response body is text (a script tag
 * in it never runs), the Authorization value never reaches the page, there is
 * no horizontal overflow, and axe finds no serious violation in the evidence
 * band.
 * Read-only.
 */

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')
const TOKEN = 'e2e-not-a-real-token-0001'

interface AxeResult {
  violations: Array<{ id: string; impact: string | null; nodes: Array<{ target: string[] }> }>
}

async function evidenceFindingId(page: Page): Promise<string | null> {
  return page.evaluate(async () => {
    const res = await fetch('/api/v1/findings?q=E2E+evidence&per_page=5')
    const body = (await res.json().catch(() => null)) as {
      data?: Array<{ id: string; title: string }>
    } | null
    return body?.data?.find((f) => f.title === 'E2E evidence 01')?.id ?? null
  })
}

for (const size of [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'phone', width: 390, height: 844 },
]) {
  test(
    `the drawer shows the request and the response (${size.name})`,
    { tag: ['@findings'] },
    async ({ page }) => {
      await page.setViewportSize({ width: 1440, height: 900 })
      await page.goto('/findings')
      await page.waitForLoadState('networkidle')
      const id = await evidenceFindingId(page)
      test.skip(!id, 'The seeded "E2E evidence 01" finding is missing')

      await page.setViewportSize({ width: size.width, height: size.height })
      // The page reads the hash once, on load: leave first so this is a load.
      await page.goto('about:blank')
      await page.goto(`/findings#finding=${id}`)
      const drawer = page.getByRole('dialog')
      await expect(drawer).toBeVisible()

      const items = drawer.getByTestId('evidence-item')
      await expect(items).toHaveCount(1)
      const item = items.first()
      await expect(item.getByText('Response', { exact: true })).toBeVisible()
      await expect(item.getByText(/^\s*200 OK/)).toBeVisible()
      await expect(item.getByTestId('evidence-match').first()).toHaveText('7.1.0')
      // Hostile body is text: the tag shows, nothing runs.
      await expect(item).toContainText('<script>window.__pwned=1</script>')
      expect(await page.evaluate(() => (window as { __pwned?: number }).__pwned)).toBeUndefined()
      // Headers are folded in the drawer; the credential inside arrives masked
      // (a chip), never as its value.
      await expect(item.getByTestId('evidence-secret').first()).toBeHidden()
      await item.getByTestId('evidence-headers').first().locator('summary').click()
      await expect(item.getByTestId('evidence-secret').first()).toBeVisible()
      expect(await page.content()).not.toContain(TOKEN)

      // Nothing wider than the drawer.
      // The seeded item also carries a long unbroken extracted value (escaped
      // slashes, no spaces): it wraps inside the item, so neither the drawer
      // nor its scrolling body scrolls sideways.
      await expect(item.getByText(/wp-json/)).toBeVisible()
      const overflow = await drawer.evaluate((el) => el.scrollWidth - el.clientWidth)
      expect(overflow).toBeLessThanOrEqual(1)
      const bodyOverflow = await drawer
        .locator('[data-slot=detail-sheet-body]')
        .evaluate((el) => el.scrollWidth - el.clientWidth)
      expect(bodyOverflow).toBeLessThanOrEqual(1)

      await test.info().attach(`drawer-evidence-${size.name}`, {
        body: await page.screenshot(),
        contentType: 'image/png',
      })

      await page.addScriptTag({ path: AXE })
      const axe = (await page.evaluate(async () => {
        const w = window as unknown as {
          axe: { run: (ctx: unknown, opts: unknown) => Promise<AxeResult> }
        }
        // The evidence band only: the drawer's Properties list has its own
        // known definition-list findings, tracked apart from this spec.
        return w.axe.run(
          { include: [['[role="dialog"] [data-testid="finding-evidence-items"]']] },
          { resultTypes: ['violations'] }
        )
      })) as AxeResult
      expect(
        axe.violations
          .filter((v) => v.impact === 'serious' || v.impact === 'critical')
          .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
      ).toEqual([])
    }
  )
}
