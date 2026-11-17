import { test, expect } from '../fixtures/authenticated-page'
import type { Page } from '@playwright/test'

/**
 * A findings row and a phone card never show a secret or an e-mail address in
 * clear. The list is stubbed with one synthetic finding whose title and
 * location hold an example.com address, a fake access key id and a URL
 * credential: the page's HTML (text, tooltips, accessible names) holds none of
 * them at desktop and phone width, the masked previews are there instead, and
 * the row offers no "Show".
 */

const EMAIL = 'admin@example.com'
const KEY = 'AKIAIOSFODNN7EXAMPLE'
const PASSWORD = 'hunter2-not-a-real-password'
const ID = '3f2504e0-4f89-41d3-9a0c-0305e82c3301'

const ROW = {
  id: ID,
  tenant_id: '00000000-0000-4000-8000-000000000001',
  asset_id: '00000000-0000-4000-8000-000000000002',
  asset: {
    id: '00000000-0000-4000-8000-000000000002',
    name: `mailbox of ${EMAIL}`,
    type: 'repository',
  },
  title: `Leaked key ${KEY} of ${EMAIL} in the build log`,
  description: 'Synthetic row',
  message: 'Synthetic row',
  severity: 'high',
  status: 'new',
  source: 'secret',
  tool_name: 'e2e',
  rule_id: `secrets.${KEY}`,
  file_path: `https://deploy:${PASSWORD}@git.example.com/app/config.yml?owner=${EMAIL}`,
  tags: [],
  first_detected_at: '2026-11-01T00:00:00Z',
  last_seen_at: '2026-11-01T00:00:00Z',
  created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-01T00:00:00Z',
}

async function stubList(page: Page) {
  await page.route(
    (url) => url.pathname === '/api/v1/findings',
    (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [ROW],
          total: 1,
          page: 1,
          per_page: 20,
          total_pages: 1,
          pagination: { page: 1, per_page: 20, total: 1, total_pages: 1 },
        }),
      })
  )
}

async function expectNothingInClear(page: Page) {
  const html = await page.content()
  for (const value of [EMAIL, KEY, PASSWORD]) expect(html).not.toContain(value)
}

test.describe('Findings masked rows', { tag: ['@findings'] }, () => {
  test('a table row shows the masked title, id and location at 1440', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await stubList(page)
    await page.goto('/findings?state=all&practice=all')
    const title = page.locator('[data-slot="finding-title-link"]').first()
    await expect(title).toBeVisible({ timeout: 20_000 })
    await expect(title).toContainText('Leaked key AKIA••••••••MPLE of ***@example.com')
    await expect(title).toHaveAttribute('href', `/findings/${ID}`)
    await expect(title).toHaveAttribute('aria-label', /AKIA••••••••MPLE of \*\*\*@example\.com/)
    await expect(page.locator('[data-slot="finding-row-id"]').first()).toHaveText(
      'secrets.AKIA••••••••MPLE'
    )
    await expect(
      page.locator('[data-slot="finding-asset-cell"] [data-slot="truncated-text"]').first()
    ).toHaveAttribute(
      'aria-label',
      /mailbox of \*\*\*@example\.com.*https:\/\/••••••••@git\.example\.com/
    )
    await expectNothingInClear(page)

    // The row menu: its title and name are masked, and it has no "Show".
    await page.getByRole('button', { name: /^Actions for Leaked key AKIA••••••••MPLE/ }).click()
    const menu = page.getByRole('menu')
    await expect(menu).toBeVisible()
    await expect(menu.getByRole('menuitem', { name: /show|reveal/i })).toHaveCount(0)
    await expectNothingInClear(page)
  })

  test('a phone card shows the masked title and place at 390', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await stubList(page)
    await page.goto('/findings?state=all&practice=all')
    const card = page.getByTestId('finding-phone-card').first()
    await expect(card).toBeVisible({ timeout: 20_000 })
    await expect(card).toContainText('Leaked key AKIA••••••••MPLE of ***@example.com')
    await expect(card.locator('[data-slot="finding-target"]')).toHaveAttribute(
      'title',
      /https:\/\/••••••••@git\.example\.com/
    )
    await expect(card.getByRole('button', { name: /show|reveal/i })).toHaveCount(0)
    await expectNothingInClear(page)
  })
})
