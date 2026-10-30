import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { layoutDefects, seriousAxe } from '../helpers/layout'

/**
 * Small defects from the 2026-10-29 mockup re-measure (research/236): a CVE
 * typed in the command palette opens the vulnerability page, the receipts list
 * says "No receipts yet" when no filter is set, and a saved dashboard's card
 * keeps all its actions inside the card at 1440px and 390px, in light and dark.
 */

const VIEWPORTS = [
  { name: '1440', width: 1440, height: 900 },
  { name: '390', width: 390, height: 844 },
] as const

async function api(page: Page, method: 'POST' | 'DELETE', url: string, data?: unknown) {
  return page.evaluate(
    async ({ method, url, data }) => {
      const r = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: data === undefined ? undefined : JSON.stringify(data),
      })
      return { status: r.status, body: await r.text() }
    },
    { method, url, data }
  )
}

for (const vp of VIEWPORTS) {
  for (const scheme of ['light', 'dark'] as const) {
    test(
      `dashboards gallery card keeps its actions inside at ${vp.name} in ${scheme}`,
      { tag: ['@dashboard'] },
      async ({ page }) => {
        await page.setViewportSize({ width: vp.width, height: vp.height })
        await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
        await page.goto('/dashboards')
        const name = `e2e-gallery-${Math.random().toString(36).slice(2, 8)} with a long dashboard name`
        const created = await api(page, 'POST', '/api/v1/me/dashboards', {
          name,
          description: 'e2e',
          columns: 4,
          layout: [],
        })
        test.skip(created.status >= 300, 'dashboard could not be created')
        const id = (JSON.parse(created.body) as { id: string }).id
        try {
          await page.reload()
          const card = page.locator('[data-slot=card]', { hasText: name })
          await expect(card).toBeVisible({ timeout: 30_000 })
          const edit = card.getByRole('button', { name: 'Edit' })
          await expect(edit).toBeVisible()
          const c = (await card.boundingBox())!
          for (const label of ['Open', 'Customize', 'Edit']) {
            const b = (await card.getByRole('button', { name: label }).boundingBox())!
            expect(b.x, `${label} left edge`).toBeGreaterThanOrEqual(c.x - 1)
            expect(b.x + b.width, `${label} right edge`).toBeLessThanOrEqual(c.x + c.width + 1)
          }
          expect(await layoutDefects(page)).toEqual([])
          expect(await seriousAxe(page)).toEqual([])
        } finally {
          await api(page, 'DELETE', `/api/v1/me/dashboards/${id}`)
        }
      }
    )

    test(
      `receipts list states for an empty list at ${vp.name} in ${scheme}`,
      { tag: ['@findings'] },
      async ({ page }) => {
        await page.setViewportSize({ width: vp.width, height: vp.height })
        await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
        await page.route('**/api/v1/findings/imports?*', (route) =>
          route.fulfill({
            contentType: 'application/json',
            body: JSON.stringify({
              data: [],
              total: 0,
              page: 1,
              per_page: 50,
              total_pages: 1,
              totals: {
                receipts: 0,
                received: 0,
                created: 0,
                updated: 0,
                reactivated: 0,
                closed: 0,
                skipped: 0,
                failed: 0,
                suppressed: 0,
              },
            }),
          })
        )
        await page.goto('/findings/imports')
        await expect(page.getByText('No receipts yet.').first()).toBeVisible({ timeout: 30_000 })
        await expect(page.getByText('No receipts match these filters.')).toHaveCount(0)
        expect(await layoutDefects(page)).toEqual([])
        expect(await seriousAxe(page)).toEqual([])
        await page.goto('/findings/imports?origin=sensor')
        await expect(page.getByText('No receipts match these filters.').first()).toBeVisible()
      }
    )
  }
}

test(
  'a CVE typed in the palette opens the vulnerability page',
  { tag: ['@shell'] },
  async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/')
    await page.waitForLoadState('networkidle')
    await page.keyboard.press('Control+k')
    await page.getByRole('dialog').locator('input').fill('CVE-2099-0101')
    await page.getByRole('option', { name: 'Open CVE-2099-0101' }).click()
    await expect(page).toHaveURL(/\/vulnerabilities\/CVE-2099-0101$/)
  }
)
