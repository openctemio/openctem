import { test, expect } from '../fixtures/authenticated-page'
import { openFindingsPhoneSelect } from '../helpers/table'

/**
 * Findings list selection. A selection belongs to the rows on screen, so a
 * page, search, sort or filter change clears it. A phone card has the row's
 * menu; "Select", first in the list's More (title row), turns the checkboxes on, and the bulk
 * bar's count selects the page or every finding that matches (en and vi at
 * 375). Skips when the stack has no findings.
 *
 * The drawer opened from a row shows the finding's place in the list ("1 of
 * N", N = the title row's count); j / k and its previous / next buttons move
 * through the page's rows, Escape closes it. The row menu has one order, as a
 * menu at 1440 and as a sheet at 390.
 */

const ROW_MENU_ORDER = [
  'View details',
  'Open to assign…',
  'Open to change status…',
  'Create ticket',
  'Add to remediation',
  'Copy ID',
  'Copy link',
  'Open to mark as false positive…',
  'Delete',
]

/** The labels shown are the full order with the items this user may not use left out. */
function expectLiveOrder(shown: string[]) {
  expect(shown[0]).toBe('View details')
  expect(shown).toContain('Copy ID')
  expect(shown).toEqual(ROW_MENU_ORDER.filter((l) => shown.includes(l)))
}

const digits = (text: string) => text.replace(/[^\d]/g, '')

const bulkBar = (page: import('@playwright/test').Page) =>
  page.getByRole('toolbar', { name: /actions for selected rows/i })

test.describe('Findings selection', { tag: ['@findings'] }, () => {
  test('a search change clears the selection', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 })
    await page.goto('/findings')
    await page.waitForLoadState('networkidle')
    const box = page.getByRole('checkbox', { name: /select finding/i }).first()
    test.skip(!(await box.isVisible().catch(() => false)), 'No selectable findings on this stack')

    await box.check()
    await expect(bulkBar(page)).toBeVisible()

    await page.getByRole('searchbox', { name: /search findings/i }).fill('zz-no-such-finding')
    await expect(bulkBar(page)).toBeHidden({ timeout: 10_000 })
  })

  test('a sort change clears the selection', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 })
    await page.goto('/findings')
    await page.waitForLoadState('networkidle')
    const box = page.getByRole('checkbox', { name: /select finding/i }).first()
    test.skip(!(await box.isVisible().catch(() => false)), 'No selectable findings on this stack')

    await box.check()
    await expect(bulkBar(page)).toBeVisible()
    // One click on a sortable header sorts by it.
    await page
      .getByRole('columnheader', { name: /^status/i })
      .getByRole('button')
      .click()
    await expect(page.getByRole('columnheader', { name: /^status/i })).toHaveAttribute(
      'aria-sort',
      /ascending|descending/
    )
    await expect(bulkBar(page)).toBeHidden({ timeout: 10_000 })
  })

  test('a phone card has a menu; Select in More turns its checkbox on', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto('/findings')
    await page.waitForLoadState('networkidle')
    const card = page.getByTestId('finding-phone-card').first()
    test.skip(!(await card.isVisible().catch(() => false)), 'No findings on this stack')

    // Outside select mode a card has no checkbox, only its menu.
    await expect(card.getByRole('checkbox')).toHaveCount(0)
    // Its long menu opens as a bottom sheet on a phone.
    await card.getByRole('button', { name: /actions for/i }).click()
    const sheet = page.locator('[data-slot="action-sheet"]')
    await expect(sheet.getByRole('button', { name: /view details/i })).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(sheet).toBeHidden()

    // Select is the first item of the list's More (title row); the toolbar
    // has no More of its own.
    await expect(page.locator('[data-slot="table-phone-more"]')).toHaveCount(0)
    await openFindingsPhoneSelect(page)
    await expect(bulkBar(page)).toBeVisible()
    await card.getByRole('checkbox').check()
    await expect(bulkBar(page).getByRole('button', { name: /selection options/i })).toHaveText(
      /^1\s/
    )
    // No page-level horizontal scroll at phone width.
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > document.documentElement.clientWidth
    )
    expect(overflow).toBe(false)
  })

  for (const locale of ['en', 'vi'] as const) {
    test(`a phone selects the page and every finding that matches (375, ${locale})`, async ({
      page,
      baseURL,
    }) => {
      await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
      await page.setViewportSize({ width: 375, height: 812 })
      await page.goto('/findings')
      await page.waitForLoadState('networkidle')
      const cards = page.getByTestId('finding-phone-card')
      test.skip(
        !(await cards
          .first()
          .isVisible()
          .catch(() => false)),
        'No findings on this stack'
      )

      await openFindingsPhoneSelect(page)
      const bar = page.locator('[data-slot="bulk-action-bar"]')
      await expect(bar).toBeVisible()
      const count = bar.locator('[data-slot="bulk-bar-select-menu"]')
      await expect(count).toHaveText(/^0\s/)
      // Nothing selected yet: the actions wait.
      for (const b of await bar.locator('[data-slot="bulk-bar-actions"] button').all()) {
        await expect(b).toBeDisabled()
      }

      // The count is the menu: the whole page first.
      await count.click()
      await page.getByRole('menuitem').first().click()
      const onPage = await cards.count()
      await expect(count).toHaveText(new RegExp(`^${onPage}\\s`))
      await expect(cards.getByRole('checkbox', { checked: false })).toHaveCount(0)

      // Then every finding that matches, when there are more than the page.
      await expect(page.getByRole('menu')).toBeHidden()
      await count.click()
      const items = page.getByRole('menuitem')
      await expect(items.first()).toBeVisible()
      if ((await items.count()) > 1) {
        const matching = items.first()
        if ((await matching.getAttribute('aria-disabled')) !== 'true') {
          await matching.click()
          await expect(count).not.toHaveText(new RegExp(`^${onPage}\\s`))
        } else await page.keyboard.press('Escape')
      } else await page.keyboard.press('Escape')
      // Closing the menu (Escape) leaves the selection as it is.
      await expect(bar).toBeVisible()

      // Every control of the bar is 36 tall, inside the screen, two lines at most.
      const boxes = await bar.evaluate((el) =>
        Array.from(el.querySelectorAll('button')).map((b) => {
          const r = b.getBoundingClientRect()
          return { h: Math.round(r.height), left: r.left, right: r.right, top: Math.round(r.top) }
        })
      )
      for (const b of boxes) {
        expect(b.h).toBe(36)
        expect(b.left).toBeGreaterThanOrEqual(0)
        expect(b.right).toBeLessThanOrEqual(375)
      }
      expect(new Set(boxes.map((b) => b.top)).size).toBeLessThanOrEqual(2)
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth > document.documentElement.clientWidth
      )
      expect(overflow).toBe(false)

      // The last card scrolls clear of the bar.
      await page.locator('#content').evaluate((m) => m.scrollTo(0, m.scrollHeight))
      const lastBottom = await cards.last().evaluate((c) => c.getBoundingClientRect().bottom)
      const barTop = await bar.evaluate((b) => b.getBoundingClientRect().top)
      expect(lastBottom).toBeLessThanOrEqual(barTop)

      // X ends select mode.
      await bar
        .getByRole('button', { name: locale === 'vi' ? 'Bỏ chọn' : 'Clear selection' })
        .click()
      await expect(bar).toBeHidden()
      await expect(cards.first().getByRole('checkbox')).toHaveCount(0)
    })
  }

  test('the drawer shows the place in the list; j, k and the buttons move; Escape closes', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings')
    await page.waitForLoadState('networkidle')
    const rows = page.locator('tbody tr')
    test.skip((await rows.count()) < 2, 'Needs two findings on this stack')

    // The count's visible number (its sentence for assistive technology is beside it).
    const total = digits(
      await page.locator('[data-slot="list-count"] [aria-hidden="true"]').first().innerText()
    )
    await rows
      .first()
      .getByRole('button', { name: /^Actions for / })
      .click()
    await page.getByRole('menuitem', { name: 'View details' }).click()
    const drawer = page.getByRole('dialog')
    await expect(drawer).toBeVisible()
    const position = drawer.locator('[data-slot="finding-drawer-position"]')
    const prev = drawer.locator('[data-slot="finding-drawer-prev"]')
    const next = drawer.locator('[data-slot="finding-drawer-next"]')

    await expect(position).toHaveText(/^1 of [\d,.]+$/)
    expect(digits((await position.innerText()).replace(/^1 of /, ''))).toBe(total)
    await expect(prev).toBeDisabled()
    await expect(next).toBeEnabled()
    const firstTitle = await drawer.getByRole('heading').first().innerText()

    // Focus is in the drawer, not in a field: a key typed there is a list move.
    await page.keyboard.press('j')
    await expect(position).toHaveText(/^2 of /)
    await expect(prev).toBeEnabled()
    await page.keyboard.press('k')
    await expect(position).toHaveText(/^1 of /)
    await expect(drawer.getByRole('heading').first()).toHaveText(firstTitle)

    await next.click()
    await expect(position).toHaveText(/^2 of /)
    await prev.click()
    await expect(position).toHaveText(/^1 of /)

    await page.keyboard.press('Escape')
    await expect(drawer).toBeHidden()
  })

  test('the row menu keeps one order as a menu at 1440', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings')
    await page.waitForLoadState('networkidle')
    const trigger = page.getByRole('button', { name: /^Actions for / }).first()
    test.skip(!(await trigger.isVisible().catch(() => false)), 'No findings on this stack')

    await trigger.click()
    const menu = page.getByRole('menu')
    await expect(menu).toBeVisible()
    // A disabled item carries its reason as a second line: the label is the first.
    const shown = await menu
      .getByRole('menuitem')
      .evaluateAll((els) =>
        els.map((e) => (e.querySelector('span > span')?.textContent ?? e.textContent ?? '').trim())
      )
    expectLiveOrder(shown)
    // Nothing is disabled without its reason.
    const unexplained = await menu
      .locator('[role="menuitem"][aria-disabled="true"]')
      .evaluateAll(
        (els) =>
          els.filter((e) => !e.parentElement?.getAttribute('aria-label')?.includes(': ')).length
      )
    expect(unexplained).toBe(0)
    await page.keyboard.press('Escape')
  })

  test(
    'the row menu keeps the same order as a sheet at 390',
    { tag: ['@phone'] },
    async ({ page }) => {
      await page.setViewportSize({ width: 390, height: 844 })
      await page.goto('/findings')
      await page.waitForLoadState('networkidle')
      const card = page.getByTestId('finding-phone-card').first()
      test.skip(!(await card.isVisible().catch(() => false)), 'No findings on this stack')

      await card.getByRole('button', { name: /^Actions for / }).click()
      const sheet = page.locator('[data-slot="action-sheet"]')
      await expect(sheet).toBeVisible()
      const rows = sheet.locator('[data-slot="action-sheet-row"]')
      const shown = await rows.evaluateAll((els) =>
        els.map((e) => (e.querySelector('span')?.textContent ?? e.textContent ?? '').trim())
      )
      expectLiveOrder(shown)
      // A disabled row shows its reason as text under the label.
      const unexplained = await sheet
        .locator('[data-slot="action-sheet-row"][aria-disabled="true"]')
        .evaluateAll(
          (els) =>
            els.filter((e) => {
              const id = e.getAttribute('aria-describedby')
              return !id || !document.getElementById(id)?.textContent?.trim()
            }).length
        )
      expect(unexplained).toBe(0)
      await page.keyboard.press('Escape')
      await expect(sheet).toBeHidden()
    }
  )
})
