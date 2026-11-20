import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { openFindingsPhoneSelect } from '../helpers/table'

/**
 * The findings list on a phone: each card reads priority and row menu, title,
 * asset, id and time left, severity and status; the footer is "Show 25 more"
 * and "25 of 60" instead of the numbered pager. Pressing it grows `per_page`
 * in the URL, keeps the cards already on screen and the scroll position, and
 * moves the focus to the first new card.
 *
 * The list response is rebuilt from the stack's own rows so that there are
 * always 60 findings to page through (the seed has fewer open ones), each
 * with an id and a deadline. Skips when the stack has no findings.
 */

const TOTAL = 60

async function sixtyFindings(page: Page) {
  await page.route(
    (url) => url.pathname === '/api/v1/findings',
    async (route) => {
      if (route.request().method() !== 'GET') return route.continue()
      const perPage = Number(new URL(route.request().url()).searchParams.get('per_page')) || 25
      const response = await route.fetch()
      const json = (await response.json()) as Record<string, unknown>
      const real = (json.data ?? []) as Record<string, unknown>[]
      if (real.length === 0) return route.fulfill({ response, json })
      const deadline = new Date(Date.now() + 5 * 86_400_000).toISOString()
      const size = Math.min(perPage, TOTAL)
      const data = Array.from({ length: size }, (_, i) => ({
        ...real[i % real.length],
        id: `${String(real[i % real.length].id)}-card-${i}`,
        title: `Card finding ${String(i + 1).padStart(2, '0')}`,
        rule_id: `e2e-card-${i + 1}`,
        cve_id: undefined,
        sla_status: 'warning',
        sla_deadline: deadline,
      }))
      await route.fulfill({
        response,
        json: {
          ...json,
          data,
          total: TOTAL,
          per_page: perPage,
          page: 1,
          total_pages: Math.ceil(TOTAL / perPage),
        },
      })
    }
  )
}

const sideways = (page: Page) =>
  page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)

test.describe('Findings phone cards', { tag: ['@findings'] }, () => {
  test('a card shows its id and time left; "Show 25 more" grows the list in place (390)', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await sixtyFindings(page)
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
    await expect(cards).toHaveCount(25)

    // The card's lines, top to bottom.
    const card = cards.first()
    const slots = await card.evaluate((el) =>
      Array.from(el.children).map((c) => c.getAttribute('data-slot'))
    )
    expect(slots).toEqual([
      'finding-card-head',
      'finding-title-cell',
      'finding-card-meta',
      'finding-card-state',
    ])
    const meta = card.locator('[data-slot="finding-card-meta"]')
    await expect(meta.locator('[data-slot="finding-row-id"]')).toHaveText('e2e-card-1')
    await expect(meta.locator('[data-slot="sla-due-chip"]')).toBeVisible()
    await expect(card).not.toContainText('·')
    // The row menu is 36 with a touch target of 44; no checkbox outside select mode.
    const menu = card.getByRole('button', { name: /actions for/i })
    const menuBox = (await menu.boundingBox())!
    expect(Math.round(menuBox.height)).toBe(36)
    expect(
      await menu.evaluate((el) => Math.round(parseFloat(getComputedStyle(el, '::before').height)))
    ).toBeGreaterThanOrEqual(44)
    await expect(card.getByRole('checkbox')).toHaveCount(0)

    // No numbered pager: one full-width button and the count.
    await expect(page.locator('[data-slot="data-table-pager"]')).toHaveCount(0)
    const more = page.locator('[data-slot="phone-show-more"]')
    await expect(more).toHaveText('Show 25 more')
    await expect(page.locator('[data-slot="phone-shown-count"]')).toHaveText('25 of 60')
    const footer = (await page.locator('[data-slot="phone-more-footer"]').boundingBox())!
    const moreBox = (await more.boundingBox())!
    expect(Math.round(moreBox.height)).toBe(36)
    expect(Math.abs(moreBox.width - footer.width)).toBeLessThanOrEqual(1)

    // Grow: the cards on screen stay where they are, the URL keeps the size.
    await more.scrollIntoViewIfNeeded()
    const last = cards.nth(24)
    const before = (await last.boundingBox())!.y
    await more.click()
    await expect(cards).toHaveCount(50)
    await expect(page).toHaveURL(/[?&]per_page=50(&|$)/)
    expect(Math.abs((await last.boundingBox())!.y - before)).toBeLessThanOrEqual(1)
    // The first new card has the focus.
    expect(
      await page.evaluate(() => {
        const all = Array.from(document.querySelectorAll('[data-phone-card]'))
        return all.indexOf(document.activeElement as Element)
      })
    ).toBe(25)
    await expect(page.locator('[data-slot="phone-shown-count"]')).toHaveText('50 of 60')

    // What is left is less than a step; then nothing more to show.
    await expect(more).toHaveText('Show 10 more')
    await more.click()
    await expect(cards).toHaveCount(60)
    await expect(page).toHaveURL(/[?&]per_page=75(&|$)/)
    await expect(more).toHaveCount(0)
    await expect(page.locator('[data-slot="phone-shown-count"]')).toHaveText('60 of 60')

    // A reload shows the same number of cards.
    await page.reload()
    await expect(cards).toHaveCount(60)
    expect(await sideways(page)).toBeLessThanOrEqual(0)
  })

  test('the cards and the footer do not scroll sideways at 375', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 })
    await sixtyFindings(page)
    await page.goto('/findings?per_page=50')
    await page.waitForLoadState('networkidle')
    const cards = page.getByTestId('finding-phone-card')
    test.skip(
      !(await cards
        .first()
        .isVisible()
        .catch(() => false)),
      'No findings on this stack'
    )
    await expect(cards).toHaveCount(50)
    await page.locator('[data-slot="phone-show-more"]').scrollIntoViewIfNeeded()
    expect(await sideways(page)).toBeLessThanOrEqual(0)
    // No card is wider than the screen.
    const widest = await cards.evaluateAll((els) =>
      Math.max(...els.map((el) => el.getBoundingClientRect().right))
    )
    expect(widest).toBeLessThanOrEqual(375)
  })

  test('select mode: the bar sits under the last card and the footer scrolls clear of it', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await sixtyFindings(page)
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
    // The checkbox is a 44 px target of its own.
    const target = (await cards.first().locator('[data-slot="finding-card-select"]').boundingBox())!
    expect(Math.round(target.width)).toBeGreaterThanOrEqual(44)
    expect(Math.round(target.height)).toBeGreaterThanOrEqual(44)
    // At the end of the list the whole footer is above the bar.
    const footer = page.locator('[data-slot="phone-more-footer"]')
    // A list page keeps its header still (a fixed layout), so the cards scroll
    // in an inner region, not in main: scroll whichever ancestor of the footer
    // scrolls.
    const scrollListToEnd = () =>
      footer.evaluate((el) => {
        for (let n = el.parentElement; n; n = n.parentElement) {
          const overflowY = getComputedStyle(n).overflowY
          if (/(auto|scroll)/.test(overflowY) && n.scrollHeight > n.clientHeight) {
            n.scrollTo(0, n.scrollHeight)
          }
        }
      })
    // Under load the cards can still be laying out when the first scroll
    // runs, so scroll again until the footer settles above the bar.
    await expect
      .poll(
        async () => {
          await scrollListToEnd()
          await footer.scrollIntoViewIfNeeded()
          await scrollListToEnd()
          const f = (await footer.boundingBox())!
          const b = (await bar.boundingBox())!
          return Math.round(f.y + f.height - b.y)
        },
        { timeout: 10_000 }
      )
      .toBeLessThanOrEqual(0)
    const b = (await bar.boundingBox())!
    expect(Math.abs(b.width - (390 - 16))).toBeLessThanOrEqual(2)
  })
})
