import { test, expect } from '../fixtures/authenticated-page'

/**
 * A remediation task is created from selected findings, opened from the
 * confirmation toast, and put on hold and resumed from its page
 * (api/docs/rfcs/RFC-098-remediation-tasks.md). The task page shows the state
 * after each change.
 *
 * A finding belongs to one open task at a time, so a rerun of this test (a
 * Playwright retry) takes the next two seeded findings instead of the ones the
 * first attempt already claimed. The CI seed has 15 findings.
 */
test('create a task from findings, then hold and resume it', async ({ page }) => {
  const title = `E2E task ${Date.now()}`
  const first = test.info().retry * 2

  await page.goto('/findings')
  await page.waitForLoadState('networkidle')

  const rows = page.getByRole('row').filter({ hasText: 'E2E finding' })
  await expect(rows.nth(first + 1)).toBeVisible({ timeout: 30_000 })
  await rows.nth(first).getByRole('checkbox', { name: 'Select row' }).check()
  await rows
    .nth(first + 1)
    .getByRole('checkbox', { name: 'Select row' })
    .check()

  // The bulk bar offers the remediation task; the dialog starts on "New task".
  await page.getByRole('button', { name: 'Remediation task' }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByRole('heading', { name: 'Add 2 findings to remediation' })).toBeVisible()
  await dialog.getByLabel('Task title').fill(title)
  await dialog.getByRole('button', { name: 'Create task' }).click()

  // Created: the toast names the task and opens it.
  await expect(page.getByText(`Task ${title} created`)).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: 'Open task' }).click()
  await expect(page).toHaveURL(/\/remediation\/tasks\/[0-9a-f-]+$/)
  await expect(page.getByRole('heading', { name: title, level: 1 })).toBeVisible()
  await expect(page.getByText('Open', { exact: true }).first()).toBeVisible()

  // Status change: hold, then resume.
  await page.getByRole('button', { name: 'More actions' }).click()
  await page.getByRole('menuitem', { name: 'Put on hold' }).click()
  await expect(page.getByText('Task put on hold')).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText('On hold', { exact: true }).first()).toBeVisible()

  await page.getByRole('button', { name: 'More actions' }).click()
  await page.getByRole('menuitem', { name: 'Resume' }).click()
  await expect(page.getByText('Task resumed')).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText('On hold', { exact: true })).toHaveCount(0)
})
