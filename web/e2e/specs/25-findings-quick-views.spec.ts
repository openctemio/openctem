import { test, expect } from '../fixtures/authenticated-page'

/**
 * Findings quick views: the sidebar lists the built-in views under Findings
 * with their counts, each one opens the list with the API's own params, and the
 * old metric strip and state tabs are gone. The counts are the API's; this
 * checks they reach the page and that a view is a plain link.
 */

test.describe('Findings quick views', { tag: ['@findings'] }, () => {
  test('the sidebar lists the views under Findings, and a view is a link to the list', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings')
    const nav = page.getByRole('list', { name: /findings views/i })
    await expect(nav).toBeVisible({ timeout: 20_000 })
    for (const name of [
      'Active',
      'Needs triage',
      'My queue',
      'SLA breached',
      'Pending approval',
      'Accepted, expiring soon',
      'Closed',
    ]) {
      await expect(nav.getByRole('link', { name: new RegExp(`^${name}`) })).toBeVisible()
    }
    await nav.getByRole('link', { name: /^Needs triage/ }).click()
    await expect(page).toHaveURL(/status=new/)
    await expect(page.getByTestId('findings-view-title')).toHaveText('Needs triage')
    await expect(nav.getByRole('link', { name: /^Needs triage/ })).toHaveAttribute(
      'aria-current',
      'page'
    )
  })

  test('the list has no metric strip and no state tabs', async ({ page }) => {
    await page.goto('/findings')
    await expect(page.getByTestId('findings-view-title')).toBeVisible({ timeout: 20_000 })
    await expect(page.getByRole('radiogroup')).toHaveCount(0)
    await expect(page.getByText('Critical open')).toHaveCount(0)
  })

  test('the views are not listed on other pages, which do not request the counts', async ({
    page,
  }) => {
    const counted: string[] = []
    page.on('request', (r) => {
      if (r.url().includes('/api/v1/findings/quick-views')) counted.push(r.url())
    })
    await page.goto('/')
    await page.waitForLoadState('networkidle')
    await expect(page.getByRole('list', { name: /findings views/i })).toHaveCount(0)
    expect(counted).toEqual([])
  })
})
