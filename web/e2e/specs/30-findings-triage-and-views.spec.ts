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
    await page.getByRole('menuitemcheckbox', { name: 'Status' }).click()
    await expect(page).toHaveURL(/columns=/)
    await page.keyboard.press('Escape')
    await page.reload()
    await expect(page.getByRole('columnheader', { name: 'Status' })).toHaveCount(0)
  })

  test('columns drop by width so the title keeps 280; the title is a link; Priority is sorted at rest', async ({
    page,
  }) => {
    const expected: Record<number, { shown: string[]; dropped: string[] }> = {
      1600: { shown: ['Severity', 'Signals and EPSS', 'Due / SLA'], dropped: [] },
      1440: { shown: ['Signals and EPSS', 'Due / SLA'], dropped: ['Severity'] },
      1280: { shown: ['Due / SLA'], dropped: ['Severity', 'Signals and EPSS'] },
      1024: { shown: [], dropped: ['Severity', 'Signals and EPSS', 'Due / SLA'] },
    }
    for (const [width, cols] of Object.entries(expected)) {
      await page.setViewportSize({ width: Number(width), height: 900 })
      await page.goto('/findings')
      const title = page.getByRole('columnheader', { name: 'Title' })
      await expect(title).toBeVisible({ timeout: 20_000 })
      const link = page.locator('[data-slot="finding-title-link"]').first()
      if (!(await link.isVisible().catch(() => false))) continue // no findings on this stack
      for (const name of cols.shown)
        await expect(page.getByRole('columnheader', { name }), `${name} at ${width}`).toHaveCount(1)
      for (const name of cols.dropped)
        await expect(page.getByRole('columnheader', { name }), `${name} at ${width}`).toHaveCount(0)
      const w = await title.evaluate((th) => th.getBoundingClientRect().width)
      expect(w, `title at ${width}`).toBeGreaterThanOrEqual(279)
      await expect(link).toHaveAttribute('href', /^\/findings\/[^/]+$/)
      await expect(page.getByRole('columnheader', { name: 'Priority' })).toHaveAttribute(
        'aria-sort',
        'descending'
      )
    }
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
