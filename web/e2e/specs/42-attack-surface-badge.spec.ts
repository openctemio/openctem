import { test, expect } from '../fixtures/authenticated-page'

/**
 * Attack surface Review (research/274): the count on the Discovery view
 * (whose Decisions lens is this page, research/353) is the number of
 * decisions the page shows. Provider addresses are never a decision.
 */

const REVIEW = '/attack-surface/review'

test('the Discovery count and the decisions page agree', { tag: ['@attack-surface'] }, async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto(REVIEW)
  const tabs = page.getByRole('navigation', { name: 'Attack surface sections' })
  await expect(tabs).toBeVisible({ timeout: 30_000 })
  await page.waitForLoadState('networkidle')
  const review = tabs.getByRole('link', { name: /^Discovery/ })
  const label = (await review.innerText()).replace(/\s+/g, ' ').trim()
  const badge = Number(label.match(/(\d+)$/)?.[1] ?? '0')
  const nothing = page.getByText('Nothing to decide')
  if (badge === 0) {
    await expect(nothing).toBeVisible()
  } else {
    await expect(nothing).toHaveCount(0)
    // Something to decide: a card that offers an action, or a suggested rule.
    await expect(
      page.getByTestId(/^decide-card-/).or(page.getByRole('heading', { name: 'Suggested rules' }))
    ).not.toHaveCount(0)
  }
})

test('provider addresses show no ports', { tag: ['@attack-surface'] }, async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto(REVIEW)
  await page.waitForLoadState('networkidle')
  const note = page.getByTestId('decide-no-decision')
  // Only when the organization has addresses that need no decision.
  if ((await note.count()) === 0) return
  await note.getByRole('button', { name: 'View list' }).click()
  await expect(note.getByTestId('decide-address-list').first()).toBeVisible()
  await expect(note.getByText(/Open ports seen/)).toHaveCount(0)
})
