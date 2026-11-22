import { test, expect } from '../fixtures/authenticated-page'

/**
 * Remediation campaigns hold tasks (server/docs/rfcs/RFC-098-remediation-tasks.md).
 * The CI seed creates one draft campaign and puts one task in it (a task of
 * its own): the campaign reads as a draft and its page lists that task.
 */
test(
  'the seeded campaign reads as a draft and lists its task',
  { tag: ['@remediation', '@smoke'] },
  async ({ page }) => {
    await page.goto('/remediation/campaigns')
    await expect(page.getByRole('heading', { name: 'Campaigns', level: 1 })).toBeVisible()

    await page.getByRole('link', { name: 'E2E remediation campaign' }).first().click()
    await expect(page.getByRole('heading', { name: 'E2E remediation campaign' })).toBeVisible()
    await expect(page.getByText('Draft').first()).toBeVisible()
    await expect(page.getByText('E2E upgrade OpenSSH on the edge hosts')).toBeVisible()
    await expect(page.getByText('This campaign has no tasks yet')).toHaveCount(0)
  }
)
