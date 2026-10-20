import { test, expect } from '../fixtures/authenticated-page'
import type { Page, TestInfo } from '@playwright/test'

/**
 * Findings list toolbar layout. Two rows that never reflow into each other:
 * row 1 = state lens + page actions, row 2 = [filter | search] + saved views,
 * Group and the table's View menu. The filter button is joined to the search
 * field, so the field can never drop onto a line of its own under the button
 * (the bug this guards), and no control may stick out past the list's edge.
 *
 * Checked at a phone, a laptop and a desktop width, with the filter panel
 * closed and (where it exists, from 1024px) open. Screenshots are attached.
 */

const WIDTHS = [375, 1024, 1280, 1440]

async function shot(page: Page, info: TestInfo, name: string) {
  await info.attach(name, { body: await page.screenshot(), contentType: 'image/png' })
}

async function checkToolbar(page: Page, label: string) {
  const primary = page.getByTestId('findings-toolbar-primary')
  const toolbar = page.getByTestId('data-table-toolbar').first()
  await expect(primary).toBeVisible()
  await expect(toolbar).toBeVisible()

  const search = toolbar.getByRole('textbox', { name: /search findings/i })
  const filter = toolbar.locator('[data-slot="filter-button"]:visible').first()
  const s = await search.boundingBox()
  const f = await filter.boundingBox()
  expect(s && f, `${label}: search and filter render`).toBeTruthy()
  if (!s || !f) return
  // Same line, search right after the button, and wide enough to type in.
  expect(Math.abs(s.y - f.y), `${label}: search wrapped under the filter button`).toBeLessThan(2)
  expect(s.x, `${label}: search sits after the filter button`).toBeGreaterThan(f.x)
  expect(s.width, `${label}: search squeezed`).toBeGreaterThanOrEqual(150)

  // The lens row comes first, the table toolbar under it.
  const p = await primary.boundingBox()
  const t = await toolbar.boundingBox()
  expect(p && t && p.y < t.y, `${label}: lens row above the search row`).toBeTruthy()

  // Nothing sticks out of either row.
  for (const [name, row] of [
    ['primary', primary],
    ['toolbar', toolbar],
  ] as const) {
    const overflow = await row.evaluate((el) => {
      const edge = el.getBoundingClientRect().right
      return [...el.querySelectorAll<HTMLElement>('button, input, [role="combobox"]')]
        .filter((c) => c.offsetParent !== null && !c.closest('.overflow-x-auto'))
        .some((c) => c.getBoundingClientRect().right > edge + 1)
    })
    expect(overflow, `${label}: a ${name} control overflows the row`).toBe(false)
  }
}

for (const width of WIDTHS) {
  test(`Findings toolbar keeps search beside the filter button (${width}px)`, async ({
    page,
  }, info) => {
    await page.setViewportSize({ width, height: 900 })
    await page.goto('/findings')
    await expect(page.getByRole('radiogroup', { name: /finding state/i })).toBeVisible({
      timeout: 20_000,
    })
    await page.waitForLoadState('networkidle')
    await shot(page, info, `${width}-panel-closed`)
    await checkToolbar(page, `${width}px panel closed`)

    if (width >= 1024) {
      const toggle = page.locator('[data-slot="filter-button"][aria-controls]').first()
      if ((await toggle.getAttribute('aria-pressed')) !== 'true') await toggle.click()
      await expect(page.locator('#finding-filters')).toBeVisible()
      // Let the panel's width transition finish before measuring.
      await page.waitForTimeout(400)
      await shot(page, info, `${width}-panel-open`)
      await checkToolbar(page, `${width}px panel open`)
    }
  })
}
