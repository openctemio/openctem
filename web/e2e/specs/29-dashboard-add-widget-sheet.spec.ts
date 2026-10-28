import { test, expect } from '../fixtures/authenticated-page'
import type { Page } from '@playwright/test'

/**
 * Customize > Add a widget. The side sheet pads its content, never scrolls
 * sideways, and nothing inside it (search field, category tabs, preview cards)
 * extends past the sheet's left or right edge. The category tabs are one
 * scrollable row: a tab hidden by that row's own scroll is not an overflow.
 * Screenshots at 1440 and 390, light and dark, are attached.
 */

async function openEditor(page: Page) {
  // A local stack may land on an organization dashboard (not editable here):
  // E2E_DASHBOARD_CHOICE="personal:<id>" opens one of the user's own.
  const choice = process.env.E2E_DASHBOARD_CHOICE
  if (choice)
    await page.addInitScript((v) => {
      window.localStorage.setItem('openctem:dashboard-choice', v)
    }, choice)
  await page.goto('/')
  await expect(page.getByTestId('dashboard-freshness')).toBeVisible({ timeout: 45_000 })
  const button = page.getByRole('button', { name: 'Customize' })
  if (await button.isVisible()) {
    await button.click()
  } else {
    const more = page.getByRole('button', { name: 'More dashboard actions' })
    test.skip((await more.count()) === 0, 'the landing dashboard is not editable')
    await more.click()
    const item = page.getByRole('menuitem', { name: 'Customize' })
    test.skip((await item.count()) === 0, 'the landing dashboard is not editable')
    await item.click()
  }
  await expect(page.getByTestId('editor-chrome').first()).toBeVisible()
}

/** Elements that stick out of the sheet's box, ignoring tabs scrolled out of their own strip. */
async function outside(page: Page): Promise<string[]> {
  return page.getByTestId('widget-gallery-sheet').evaluate((sheet) => {
    const box = sheet.getBoundingClientRect()
    const out: string[] = []
    for (const el of sheet.querySelectorAll<HTMLElement>('*')) {
      if (el.closest('[data-slot="tabs-list"]') && !el.matches('[data-slot="tabs-list"]')) continue
      const r = el.getBoundingClientRect()
      if (!r.width || !r.height) continue
      if (r.left < box.left - 0.5 || r.right > box.right + 0.5) {
        out.push(
          `${el.tagName}.${String(el.className).slice(0, 50)} ${Math.round(r.left - box.left)}`
        )
      }
    }
    return out
  })
}

for (const vp of [
  { width: 1440, height: 1000 },
  { width: 390, height: 844 },
] as const) {
  for (const scheme of ['light', 'dark'] as const) {
    test(
      `add-widget sheet stays inside itself at ${vp.width}px in ${scheme}`,
      { tag: ['@dashboard'] },
      async ({ page }, info) => {
        await page.setViewportSize(vp)
        await page.emulateMedia({ colorScheme: scheme })
        await openEditor(page)
        await page
          .getByRole('button', { name: /Add (a )?widget/i })
          .first()
          .click()
        const sheet = page.getByTestId('widget-gallery-sheet')
        await expect(sheet).toBeVisible()
        await expect(sheet.locator('[data-testid^="gallery-card-"]').first()).toBeVisible()

        const box = await sheet.boundingBox()
        expect(box && box.width).toBeLessThanOrEqual(Math.min(34 * 16, vp.width) + 0.5)
        // Full screen on a phone (a scroll-lock scrollbar gutter may take a few pixels).
        if (vp.width < 640) expect(box && box.width).toBeGreaterThanOrEqual(vp.width - 24)

        // Let the lazy previews load and scroll through them: a wide one would
        // stretch the whole list.
        const body = sheet.locator('[data-slot="sheet-body"]')
        for (let i = 0; i < 4; i++) {
          await body.evaluate((el) => el.scrollBy(0, 600))
          await page.waitForTimeout(400)
        }
        await body.evaluate((el) => el.scrollTo(0, 0))
        expect(await outside(page)).toEqual([])
        const sideways = await body.evaluate((el) => el.scrollWidth - el.clientWidth)
        expect(sideways).toBeLessThanOrEqual(1)
        expect(
          await page.evaluate(
            () => document.documentElement.scrollWidth - document.documentElement.clientWidth
          )
        ).toBeLessThanOrEqual(0)

        // The tablist is a single row with a roving tabindex: at most one tab stop among the tabs.
        const tabs = sheet.getByRole('tab')
        expect(await tabs.count()).toBeGreaterThanOrEqual(5)
        const stops = await tabs.evaluateAll((all) => all.filter((t) => t.tabIndex === 0).length)
        expect(stops).toBeLessThanOrEqual(1)
        const tops = await tabs.evaluateAll(
          (all) => new Set(all.map((t) => Math.round(t.getBoundingClientRect().top))).size
        )
        expect(tops, 'tabs wrapped onto a second line').toBe(1)

        await info.attach(`add-widget-${vp.width}-${scheme}.png`, {
          body: await page.screenshot(),
          contentType: 'image/png',
        })
        await page.keyboard.press('Escape')
        await expect(sheet).toBeHidden()
      }
    )
  }
}
