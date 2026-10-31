import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import templates from '../../src/features/dashboards/templates.json'

/**
 * Dashboard actions on a personal copy of the CTEM template, at 1440px and
 * 390px: the view toolbar and the editor toolbar keep every button apart and
 * inside the page (no sideways scroll); the editor toolbar stays in sight
 * below the app header while the widgets scroll; a widget added from the
 * gallery is shown and focused once its settings close; Cancel with changes
 * asks first; "Edit details" opens this dashboard's details form.
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

/** Visible buttons of `root` that overlap each other or leave the viewport. */
async function crowded(page: Page, selector: string): Promise<string[]> {
  return page.locator(selector).evaluate((root) => {
    const vw = document.documentElement.clientWidth
    const boxes = [...root.querySelectorAll<HTMLElement>('button')]
      .filter((b) => b.offsetParent !== null)
      .map((b) => ({
        name: b.getAttribute('aria-label') || b.textContent?.trim(),
        r: b.getBoundingClientRect(),
      }))
      .filter((b) => b.r.width > 0)
    const out: string[] = []
    boxes.forEach((a, i) => {
      if (a.r.left < -0.5 || a.r.right > vw + 0.5) out.push(`${a.name} outside the page`)
      for (const b of boxes.slice(i + 1)) {
        const apart =
          a.r.right <= b.r.left + 0.5 ||
          b.r.right <= a.r.left + 0.5 ||
          a.r.bottom <= b.r.top + 0.5 ||
          b.r.bottom <= a.r.top + 0.5
        if (!apart) out.push(`${a.name} overlaps ${b.name}`)
      }
    })
    return out
  })
}

const sideways = (page: Page) =>
  page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)

for (const vp of VIEWPORTS) {
  test(
    `dashboard and editor actions work and fit at ${vp.name}px`,
    { tag: ['@dashboard'] },
    async ({ page }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height })
      await page.goto('/dashboards')
      const ctem = templates.find((t) => t.key === 'ctem')!
      const created = await api(page, 'POST', '/api/v1/me/dashboards', {
        name: `e2e-editor-${Math.random().toString(36).slice(2, 8)}`,
        columns: ctem.columns,
        layout: ctem.widgets.map((w, i) => ({ ...w, x: 0, y: i })),
      })
      test.skip(created.status >= 300, 'dashboard could not be created')
      const id = (JSON.parse(created.body) as { id: string }).id
      try {
        await page.evaluate(
          (v) => window.localStorage.setItem('openctem:dashboard-choice', v),
          `personal:${id}`
        )
        await page.goto('/')
        await expect(page.getByTestId('dashboard-freshness')).toBeVisible({ timeout: 45_000 })
        expect(await crowded(page, '[data-testid=dashboard-toolbar]')).toEqual([])
        expect(await sideways(page)).toBeLessThanOrEqual(0)

        // Edit details opens this dashboard's form.
        await page.getByRole('button', { name: 'More dashboard actions' }).click()
        await expect(page.getByRole('menuitem', { name: 'Edit details' })).toHaveAttribute(
          'href',
          `/dashboards?edit=${id}`
        )

        // Customize (in the More menu on a phone).
        const customize = page.getByRole('menuitem', { name: 'Customize' })
        if (await customize.isVisible()) await customize.click()
        else {
          await page.keyboard.press('Escape')
          await page.getByRole('button', { name: 'Customize' }).click()
        }
        const toolbar = page.getByRole('toolbar', { name: 'Dashboard editor' })
        await expect(toolbar).toBeVisible()
        expect(await crowded(page, '[role=toolbar]')).toEqual([])
        expect(await sideways(page)).toBeLessThanOrEqual(0)

        // The toolbar stays in sight below the app header while the widgets scroll.
        await page.getByTestId('editor-card').last().scrollIntoViewIfNeeded()
        const header = await page.locator('header').first().boundingBox()
        const bar = (await toolbar.boundingBox())!
        expect(bar.y).toBeGreaterThanOrEqual((header?.y ?? 0) + (header?.height ?? 0) - 1)
        expect(bar.y + bar.height).toBeLessThanOrEqual(vp.height)

        // A widget added from the gallery is shown and focused after Apply.
        const before = await page.getByTestId('editor-card').count()
        await toolbar.getByRole('button', { name: 'Add widget' }).click()
        await page.getByPlaceholder('Search widgets').fill('KEV')
        await page
          .locator('[data-testid="gallery-card-intel.kev_open"]')
          .getByRole('button', { name: /^Add / })
          .click()
        await page.getByRole('dialog').getByRole('button', { name: 'Apply' }).click()
        await expect(page.getByTestId('editor-card')).toHaveCount(before + 1)
        const added = page.getByTestId('editor-card').last()
        await expect(added).toBeFocused()
        await expect(added).toBeInViewport()

        // Cancel with a change asks first; Discard leaves the dashboard unchanged.
        await toolbar.getByRole('button', { name: 'Cancel' }).click()
        const ask = page.getByRole('alertdialog')
        await expect(ask).toBeVisible()
        await ask.getByRole('button', { name: 'Discard changes' }).click()
        await expect(page.locator('[data-widget-index]')).toHaveCount(before)
      } finally {
        await api(page, 'DELETE', `/api/v1/me/dashboards/${id}`)
      }
    }
  )
}
