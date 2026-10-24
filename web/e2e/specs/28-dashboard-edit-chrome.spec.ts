import { test, expect } from '../fixtures/authenticated-page'
import type { Page } from '@playwright/test'

/**
 * Dashboard edit mode (Customize). Each widget header holds the drag handle,
 * the title, Configure and a More menu; nothing in it may stick out of its
 * widget, even on the narrow (one column of four) tiles, and the title keeps
 * readable room. On a phone the editor is a single-column list with 44px
 * targets. Screenshots at 1440 and 390, light and dark, are attached.
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

/** Controls of a chrome row that stick out past its right edge (or are clipped). */
async function overflowing(page: Page): Promise<string[]> {
  return page.getByTestId('editor-chrome').evaluateAll((rows) =>
    rows.flatMap((row, i) => {
      const edge = row.getBoundingClientRect()
      return [...row.querySelectorAll<HTMLElement>('button')]
        .filter((b) => b.offsetParent !== null)
        .filter((b) => {
          const r = b.getBoundingClientRect()
          return r.right > edge.right + 0.5 || r.left < edge.left - 0.5
        })
        .map((b) => `widget ${i}: ${b.getAttribute('aria-label')}`)
    })
  )
}

for (const vp of [
  { name: 'desktop', width: 1440, height: 1000 },
  { name: 'phone', width: 390, height: 844 },
] as const) {
  for (const scheme of ['light', 'dark'] as const) {
    test(`edit mode chrome fits every widget at ${vp.width}px in ${scheme}`, async ({
      page,
    }, info) => {
      await page.setViewportSize({ width: vp.width, height: vp.height })
      await page.emulateMedia({ colorScheme: scheme })
      await openEditor(page)

      expect(await overflowing(page)).toEqual([])
      const titles = page.getByTestId('editor-chrome').locator('span[title]')
      for (const title of await titles.all()) {
        const box = await title.boundingBox()
        expect(box && box.width, 'title squeezed out').toBeGreaterThan(40)
      }

      if (vp.width < 640) {
        // One column: every card starts at the same x and spans the list.
        const xs = await page
          .getByTestId('editor-card')
          .evaluateAll((cards) => cards.map((c) => Math.round(c.getBoundingClientRect().left)))
        expect(new Set(xs).size).toBe(1)
        const buttons = page.getByTestId('editor-chrome').first().locator('button:visible')
        for (const b of await buttons.all()) {
          const box = await b.boundingBox()
          if (box) expect(box.height).toBeGreaterThanOrEqual(43.5)
        }
        const overflow = await page.evaluate(
          () => document.documentElement.scrollWidth - document.documentElement.clientWidth
        )
        expect(overflow).toBeLessThanOrEqual(0)
      }

      await info.attach(`edit-${vp.width}-${scheme}.png`, {
        body: await page.screenshot(),
        contentType: 'image/png',
      })
      // The More menu holds the move, resize, duplicate and remove actions.
      await page
        .getByTestId('editor-chrome')
        .first()
        .getByRole('button', { name: /^More actions for / })
        .click()
      await expect(page.getByRole('menuitem', { name: /Remove/ })).toBeVisible()
      await info.attach(`edit-${vp.width}-${scheme}-menu.png`, {
        body: await page.screenshot(),
        contentType: 'image/png',
      })
    })
  }
}
