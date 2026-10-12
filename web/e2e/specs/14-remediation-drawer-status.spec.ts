import { test, expect } from '../fixtures/authenticated-page'
import { firstDataRow } from '../helpers/table'

/**
 * The remediation task drawer follows a status change made from it.
 *
 * Regression: after a transition the page overwrote the open drawer's task
 * with campaign data captured BEFORE the refresh, so the drawer kept the old
 * status and its old actions (after "Start Task" it still offered "Start
 * Task") while the list showed the new one.
 *
 * Needs a remediation task (the CI seed creates one). The test leaves the
 * task in progress, the state "Start Task" leads to, so a rerun starts from
 * the same place.
 */
test('the task drawer shows the new status after a transition', async ({ page }) => {
  await page.goto('/remediation')
  const row = await firstDataRow(page)
  test.skip(!row, 'no remediation tasks in this tenant')
  await row!.click()

  const drawer = page.getByRole('dialog')
  const start = drawer.getByRole('button', { name: 'Start Task' })
  const block = drawer.getByRole('button', { name: 'Block' })
  const unblock = drawer.getByRole('button', { name: 'Unblock' })
  await expect(start.or(block).or(unblock).first()).toBeVisible({ timeout: 15_000 })

  if (await start.isVisible()) {
    await start.click()
    await expect(block).toBeVisible({ timeout: 10_000 })
  } else if (await unblock.isVisible()) {
    await unblock.click()
    await expect(block).toBeVisible({ timeout: 10_000 })
  }

  await block.click()
  await expect(unblock).toBeVisible({ timeout: 10_000 })
  await unblock.click()
  await expect(block).toBeVisible({ timeout: 10_000 })
})
