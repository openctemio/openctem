import { test, expect } from '../fixtures/authenticated-page'
import type { Page } from '@playwright/test'

/**
 * Findings list states. A failed list shows inline in the table area, with the
 * header, search and filter button still there and no toast on top; a refused
 * read says so; an empty organization says it has no findings yet. The API
 * answers are stubbed, so the stack needs no particular data.
 */

const listUrl = (url: URL) => url.pathname === '/api/v1/findings'

async function stubList(page: Page, status: number, body: unknown) {
  await page.route(
    (url) => listUrl(url),
    (route) =>
      route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
  )
}

test.describe('Findings states', { tag: ['@findings'] }, () => {
  test('a failed list is an inline error with Retry, and no toast', async ({ page }) => {
    await stubList(page, 500, {
      error: { code: 'INTERNAL_ERROR', message: 'database is down', request_id: 'req-e2e-1' },
    })
    await page.goto('/findings')
    await expect(page.getByRole('alert').filter({ hasText: /failed to load/i })).toBeVisible({
      timeout: 20_000,
    })
    // The page chrome stays.
    await expect(page.getByRole('heading', { name: 'Findings', level: 1 })).toBeVisible()
    await expect(page.getByRole('searchbox', { name: /search findings/i })).toBeVisible()
    await expect(page.getByRole('button', { name: /copy request id/i })).toBeVisible()
    await expect(page.getByRole('button', { name: /retry/i })).toBeVisible()
    // One message, not an inline error plus a toast.
    await expect(page.locator('[data-sonner-toast]')).toHaveCount(0)
  })

  test('a refused read says access is missing', async ({ page }) => {
    await stubList(page, 403, {
      error: {
        code: 'FORBIDDEN',
        message: 'forbidden',
        details: { missing_permissions: ['findings:read'] },
      },
    })
    await page.goto('/findings')
    await expect(page.getByText('You do not have access to these findings')).toBeVisible({
      timeout: 20_000,
    })
    await expect(page.getByRole('heading', { name: 'Findings', level: 1 })).toBeVisible()
  })

  test('an organization with no findings offers the way to bring some in', async ({ page }) => {
    await stubList(page, 200, {
      data: [],
      total: 0,
      page: 1,
      per_page: 20,
      total_pages: 0,
      pagination: { page: 1, per_page: 20, total: 0, total_pages: 0 },
    })
    await page.route(
      (url) => url.pathname === '/api/v1/findings/stats',
      (route) =>
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            total: 0,
            by_severity: {},
            by_status: {},
            by_source: {},
            open_count: 0,
            resolved_count: 0,
            by_state: { open: 0, fixed: 0, dispositioned: 0, all: 0 },
          }),
        })
    )
    await page.goto('/findings')
    await expect(page.getByText('No findings in this organization yet')).toBeVisible({
      timeout: 20_000,
    })
    await expect(page.getByRole('link', { name: /set up a scan/i })).toBeVisible()
  })

  test('a search that hides everything says what is hidden and clears itself', async ({ page }) => {
    await stubList(page, 200, {
      data: [],
      total: 0,
      page: 1,
      per_page: 20,
      total_pages: 0,
      pagination: { page: 1, per_page: 20, total: 0, total_pages: 0 },
    })
    await page.goto('/findings?q=zz-nothing')
    await expect(page.getByText('No findings match')).toBeVisible({ timeout: 20_000 })
    await page
      .getByTestId('findings-empty-state')
      .getByRole('button', { name: 'Clear search' })
      .click()
    await expect(page).not.toHaveURL(/q=zz-nothing/)
  })
})
