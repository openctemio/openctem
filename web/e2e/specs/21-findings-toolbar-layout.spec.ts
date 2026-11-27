import { test, expect } from '../fixtures/authenticated-page'
import type { Page, TestInfo } from '@playwright/test'

/**
 * Findings list toolbar layout. Two rows that never reflow into each other:
 * row 1 = view title + page actions, row 2 = search, the fixed scopes
 * (Practice, State) and Add filter, then saved views, Group and the table's
 * View menu. Below 1024px the Filters button (the sheet) is joined to the
 * search field, so the field can never drop onto a line of its own under the
 * button (the bug this guards); from 1024px there is no Filters button, Add
 * filter opens the facet panel. No control may stick out past the list's edge.
 *
 * Checked at a phone, a laptop and a desktop width, with the filter panel
 * closed and (from 1024px) open. Screenshots are attached.
 */

const WIDTHS = [375, 1024, 1280, 1440]

async function shot(page: Page, info: TestInfo, name: string) {
  await info.attach(name, { body: await page.screenshot(), contentType: 'image/png' })
}

async function checkToolbar(page: Page, label: string, wide: boolean, oneLine = wide) {
  const primary = page.getByTestId('findings-toolbar-primary')
  const toolbar = page.getByTestId('data-table-toolbar').first()
  // The toolbar's box, or with a chips row the region around it: on a narrow
  // list the toolbar lends its controls to that region and has no box itself.
  const toolbarBox = page
    .locator('[data-slot="list-toolbar-region"], [data-testid="data-table-toolbar"]')
    .first()
  await expect(primary).toBeVisible()
  await expect(toolbarBox).toBeVisible()

  const search = toolbar.getByRole('searchbox', { name: /search findings/i })
  const s = await search.boundingBox()
  expect(s, `${label}: search renders`).toBeTruthy()
  if (!s) return
  expect(s.width, `${label}: search squeezed`).toBeGreaterThanOrEqual(150)
  if (wide) {
    // One filter entry: no Filters button; the fixed scopes and Add filter
    // follow the search on its line.
    await expect(toolbar.locator('[data-slot="filter-button"]:visible')).toHaveCount(0)
    // A toolbar under 28rem wide (the open panel at 1024) lays out as on a
    // phone: its scopes are held by the open panel, not drawn in the toolbar.
    if (((await toolbarBox.boundingBox())?.width ?? 0) < 448) return
    for (const name of [/^Practice: /, /^State: /, /^Add filter$/]) {
      const b = await toolbar.getByRole('button', { name }).boundingBox()
      expect(b, `${label}: ${name} renders`).toBeTruthy()
      if (!b || !oneLine) continue
      expect(
        Math.abs(b.y + b.height / 2 - (s.y + s.height / 2)),
        `${label}: ${name} off the search line`
      ).toBeLessThan(2)
      expect(b.x, `${label}: ${name} comes after the search`).toBeGreaterThan(s.x)
    }
  } else {
    const f = await toolbar.locator('[data-slot="filter-button"]:visible').first().boundingBox()
    expect(f, `${label}: filter button renders`).toBeTruthy()
    if (!f) return
    // Same line, search right after the button.
    expect(Math.abs(s.y - f.y), `${label}: search wrapped under the filter button`).toBeLessThan(2)
    expect(s.x, `${label}: search sits after the filter button`).toBeGreaterThan(f.x)
  }

  // The lens row comes first, the table toolbar under it.
  const p = await primary.boundingBox()
  const t = await toolbarBox.boundingBox()
  expect(p && t && p.y < t.y, `${label}: lens row above the search row`).toBeTruthy()

  // The view title keeps readable room inside the primary row (at phone width
  // the Awaiting verification button used to squeeze it to nothing).
  const title = await page.getByTestId('findings-view-title').boundingBox()
  const row = await primary.boundingBox()
  expect(title && title.width >= 32, `${label}: the view title has room`).toBeTruthy()
  expect(
    title && row && title.x >= row.x - 1,
    `${label}: the view title starts inside the row`
  ).toBeTruthy()

  // Nothing sticks out of either row.
  for (const [name, row] of [
    ['primary', primary],
    ['toolbar', toolbarBox],
  ] as const) {
    const overflow = await row.evaluate((el) => {
      const edge = el.getBoundingClientRect().right
      // A control inside a strip that scrolls sideways is clipped by it, not
      // drawn past the row (the class may be a container variant, so the
      // computed style decides).
      const inScroller = (c: HTMLElement) => {
        for (let p = c.parentElement; p && p !== el; p = p.parentElement) {
          if (getComputedStyle(p).overflowX !== 'visible') return true
        }
        return false
      }
      return [...el.querySelectorAll<HTMLElement>('button, input, [role="combobox"]')]
        .filter((c) => c.offsetParent !== null && !inScroller(c))
        .some((c) => c.getBoundingClientRect().right > edge + 1)
    })
    expect(overflow, `${label}: a ${name} control overflows the row`).toBe(false)
  }
}

for (const width of WIDTHS) {
  test(
    `Findings toolbar keeps search beside the filter button (${width}px)`,
    { tag: ['@findings'] },
    async ({ page }, info) => {
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/findings')
      await expect(page.getByTestId('findings-view-title')).toBeVisible({
        timeout: 20_000,
      })
      await page.waitForLoadState('networkidle')
      await shot(page, info, `${width}-panel-closed`)
      const wide = width >= 1024
      await checkToolbar(page, `${width}px panel closed`, wide)

      if (wide) {
        // The slot is inert while the panel is closed.
        const slot = page.locator('#finding-filters').locator('xpath=..')
        if ((await slot.getAttribute('inert')) !== null) {
          await page
            .getByTestId('data-table-toolbar')
            .getByRole('button', { name: 'Add filter' })
            .click()
          await page.getByRole('button', { name: 'Show the filter panel' }).click()
        }
        await expect(page.locator('#finding-filters')).toBeVisible()
        // Let the panel's width transition finish before measuring.
        await page.waitForTimeout(400)
        await shot(page, info, `${width}-panel-open`)
        // The open panel takes 276 px from the list: below 1440 the scopes
        // and Add filter may take a second line there (no overflow, no
        // squeezed field); from 1440 they keep the search line.
        await checkToolbar(page, `${width}px panel open`, wide, width >= 1440)
        // The panel closes from its own header.
        await page.getByRole('button', { name: 'Hide the filter panel' }).click()
        await expect(slot).toHaveAttribute('inert', '')
      }
    }
  )
}
