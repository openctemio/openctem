import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * The shared query editor in a dialog (Findings, "Task from filters"): its
 * suggestion list floats above the dialog (no scroll container clips it, the
 * footer never paints over it), keeps the hint under the field readable, shows
 * at least five rows when there is room, and Escape closes it before the
 * dialog. The editor shows the characters typed: no font ligatures (`!=` is
 * never drawn as one glyph). Needs no particular data: the field names come
 * from the query schema.
 */

async function openTaskDialog(page: Page) {
  await page.goto('/findings')
  const direct = page.getByRole('button', { name: /^(task from filters|nhiệm vụ từ bộ lọc)$/i })
  if (await direct.isVisible({ timeout: 20_000 }).catch(() => false)) {
    await direct.click()
  } else {
    await page
      .locator('[data-slot="page-header"], main')
      .getByRole('button', { name: /more actions|thao tác khác/i })
      .first()
      .click()
    await page.getByRole('menuitem', { name: /task from filters|nhiệm vụ từ bộ lọc/i }).click()
  }
  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  return dialog
}

async function checkSuggestions(page: Page, touch: boolean) {
  const dialog = await openTaskDialog(page)
  const box = dialog.getByRole('combobox')
  await expect(box).toBeVisible()
  // Literal characters: ligatures and contextual alternates are off.
  const features = await box.evaluate((el) => {
    const cs = getComputedStyle(el)
    return { ligatures: cs.fontVariantLigatures, settings: cs.fontFeatureSettings }
  })
  expect(features.ligatures).toBe('none')
  expect(features.settings).toContain('"liga" 0')
  expect(features.settings).toContain('"calt" 0')

  if (touch) await box.tap()
  else await box.click()
  await box.fill('a')
  const list = page.getByRole('listbox')
  await expect(list).toBeVisible()

  const vp = page.viewportSize()!
  const lb = (await list.boundingBox())!
  expect(lb.y).toBeGreaterThanOrEqual(0)
  expect(lb.x).toBeGreaterThanOrEqual(0)
  expect(lb.y + lb.height).toBeLessThanOrEqual(vp.height)
  expect(lb.x + lb.width).toBeLessThanOrEqual(vp.width)
  // Never wider than the field.
  const fb = (await box.boundingBox())!
  expect(lb.width).toBeLessThanOrEqual(fb.width + 1)

  // The list lives outside the dialog: no scroll container can clip it.
  expect(await dialog.locator('[role="listbox"]').count()).toBe(0)

  // At least five rows, each fully visible and on top (the footer never
  // paints over a row).
  const options = list.getByRole('option')
  const n = await options.count()
  expect(n).toBeGreaterThanOrEqual(5)
  let onTop = 0
  for (let i = 0; i < n; i++) {
    const r = await options.nth(i).boundingBox()
    if (!r || r.y < lb.y || r.y + r.height > lb.y + lb.height + 0.5) continue
    const hit = await page.evaluate(
      ({ x, y }) => !!document.elementFromPoint(x, y)?.closest('[role="listbox"]'),
      { x: r.x + r.width / 2, y: r.y + r.height / 2 }
    )
    if (hit) onTop++
  }
  expect(onTop).toBeGreaterThanOrEqual(5)
  const footer = dialog.locator('[data-slot="dialog-footer"]')
  const footerOverList = await page.evaluate(() => {
    const f = document.querySelector('[data-slot="dialog-footer"]')?.getBoundingClientRect()
    const l = document.querySelector('[role="listbox"]')?.getBoundingClientRect()
    if (!f || !l) return false
    const x = Math.max(f.left, l.left) + 2
    const y = Math.max(f.top, l.top) + 2
    if (x > Math.min(f.right, l.right) || y > Math.min(f.bottom, l.bottom)) return false
    return !document.elementFromPoint(x, y)?.closest('[role="listbox"]')
  })
  expect(footerOverList).toBe(false)
  await expect(footer).toBeVisible()

  // The hint under the field stays readable: the list does not cover it.
  const statusId = await box.getAttribute('aria-describedby')
  const sb = (await page.locator(`[id="${statusId}"]`).boundingBox())!
  const overlaps =
    sb.x < lb.x + lb.width &&
    lb.x < sb.x + sb.width &&
    sb.y < lb.y + lb.height &&
    lb.y < sb.y + sb.height
  expect(overlaps).toBe(false)

  // Escape closes the list first and keeps the dialog.
  await box.press('Escape')
  await expect(list).toBeHidden()
  await expect(dialog).toBeVisible()
  await expect(box).toHaveAttribute('aria-expanded', 'false')
}

test.describe('Query editor in a dialog', { tag: ['@findings'] }, () => {
  for (const locale of ['en', 'vi'] as const) {
    test(`suggestions float above the dialog, literal characters (1440, ${locale})`, async ({
      page,
      baseURL,
    }) => {
      await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
      await page.setViewportSize({ width: 1440, height: 900 })
      await checkSuggestions(page, false)
    })
  }
})

test.describe('Query editor in a dialog on a phone', { tag: ['@findings'] }, () => {
  test.use({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })
  for (const locale of ['en', 'vi'] as const) {
    test(`suggestions float above the sheet, no keyboard on open (390 touch, ${locale})`, async ({
      page,
      baseURL,
    }) => {
      await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
      const dialog = await openTaskDialog(page)
      // The dialog does not focus the editor by itself on touch.
      await expect(dialog.getByRole('combobox')).not.toBeFocused()
      await page.keyboard.press('Escape')
      await checkSuggestions(page, true)
    })
  }
})
