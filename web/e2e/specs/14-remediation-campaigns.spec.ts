import { test, expect } from '../fixtures/authenticated-page'

/**
 * Remediation campaigns hold tasks (api/docs/rfcs/RFC-098-remediation-tasks.md).
 * The CI seed creates one draft campaign with no task: the list shows it as
 * "Draft" and its page offers to add tasks.
 */
test('the seeded campaign reads as a draft with no tasks yet', async ({ page }) => {
  await page.goto('/remediation/campaigns')
  await expect(page.getByRole('heading', { name: 'Campaigns', level: 1 })).toBeVisible()

  await page.getByRole('link', { name: 'E2E remediation campaign' }).first().click()
  await expect(page.getByRole('heading', { name: 'E2E remediation campaign' })).toBeVisible()
  await expect(page.getByText('Draft').first()).toBeVisible()
  await expect(page.getByText('This campaign has no tasks yet')).toBeVisible()
})
