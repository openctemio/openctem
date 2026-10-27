import { test, expect } from '../fixtures/authenticated-page'

/**
 * Findings: Triage is the primary action (it opens triage mode), Priority and Finding are always
 * columns, columns and density are kept in the URL (and saved with a view), and
 * a view with changes shows the unsaved-changes dot. Needs no particular data.
 */

test.describe('Findings triage and view state', { tag: ['@findings'] }, () => {
  test('Triage is the one primary button and opens triage mode; Esc comes back', async ({
    page,
  }) => {
    await page.goto('/findings?severity=critical')
    const triage = page.getByRole('button', { name: /^Triage/ })
    await expect(triage).toBeVisible({ timeout: 20_000 })
    await triage.click()
    await expect(page).toHaveURL(/\/findings\/triage\?status=new/)
    await expect(page.getByTestId('triage-top-bar')).toContainText('Needs triage')
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur())
    await page.keyboard.press('Escape')
    await expect(page).toHaveURL(/\/findings\?severity=critical$/)
  })

  test('Priority and Finding stay when other columns are hidden', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings?columns=')
    await expect(page.getByRole('columnheader', { name: 'Title' })).toBeVisible({ timeout: 20_000 })
    await expect(page.getByRole('columnheader', { name: 'Priority' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Status' })).toHaveCount(0)
  })

  test('hiding a column through View is kept in the URL and survives a reload', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings?status=new&state=all')
    await page.getByRole('button', { name: /^display: density/i }).click()
    await page.getByRole('menuitemcheckbox', { name: 'Severity' }).click()
    await expect(page).toHaveURL(/columns=/)
    await page.keyboard.press('Escape')
    await page.reload()
    await expect(page.getByRole('columnheader', { name: 'Severity' })).toHaveCount(0)
  })

  test('there is no page-level horizontal scroll at 1024, 1280 and 1440', async ({ page }) => {
    for (const width of [1024, 1280, 1440]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/findings?columns=severity,asset,source,status,slaStatus,createdAt')
      await expect(page.getByTestId('findings-view-title')).toBeVisible({ timeout: 20_000 })
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth > document.documentElement.clientWidth
      )
      expect(overflow, `${width}px`).toBe(false)
    }
  })
})
