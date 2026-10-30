import { test, expect } from '../fixtures/authenticated-page'
import type { Page } from '@playwright/test'

/**
 * A ticketing connection that failed its test says what is wrong in words
 * and offers the fix; no entity id or upstream error ever reaches the page
 * (the owner's report: "Connection test failed: integration <uuid> has no
 * credentials"). The API answers are stubbed, so the stack needs no data.
 */

const ID = '99999999-9999-4999-8999-999999999999'
const LEAKY = `Connection test failed: integration ${ID} has no credentials`
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i

const failed = {
  id: ID,
  name: 'Jira SEC',
  category: 'ticketing',
  provider: 'jira',
  status: 'error',
  status_code: 'INTEGRATION_NO_CREDENTIALS',
  status_message: LEAKY,
  auth_type: 'token',
  supported: true,
  sync_interval_minutes: 60,
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
}

async function stub(page: Page) {
  await page.route(
    (url) => url.pathname === '/api/v1/integrations',
    (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: [failed], total: 1, page: 1, per_page: 50, total_pages: 1 }),
      })
  )
  await page.route(
    (url) => url.pathname === `/api/v1/integrations/${ID}/test`,
    (route) =>
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(failed) })
  )
}

test.describe('Ticketing connection errors', { tag: ['@ticketing'] }, () => {
  test('a connection without a token says so, offers the fix and never shows the id', async ({
    page,
  }) => {
    await stub(page)
    await page.goto('/settings/integrations/ticketing')
    const message = 'This connection has no API token. Add one to use it.'
    await expect(page.getByText(message).first()).toBeVisible({ timeout: 20_000 })

    // Test connection from the row menu: the toast uses the same words.
    await page
      .getByRole('row', { name: /Jira SEC/ })
      .getByRole('button')
      .last()
      .click()
    await expect(page.getByRole('menuitem', { name: 'Add API token' })).toBeVisible()
    await page.getByRole('menuitem', { name: /test connection/i }).click()
    await expect(page.locator('[data-sonner-toast]').filter({ hasText: message })).toBeVisible()

    // The fix opens the token form.
    await page
      .getByRole('row', { name: /Jira SEC/ })
      .getByRole('button')
      .last()
      .click()
    await page.getByRole('menuitem', { name: 'Add API token' }).click()
    await expect(page.getByRole('dialog', { name: /API token for Jira SEC/ })).toBeVisible()

    const text = await page.locator('body').innerText()
    expect(text).not.toMatch(UUID_RE)
    expect(text).not.toContain('Connection test failed: integration')
  })
})
