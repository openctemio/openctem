import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Attack surface › Page changes (RFC-138): the change list, the diff sheet
 * with a hostile script source shown as text, and the watch list, on a
 * desktop and a phone. The page monitoring API is answered by the test so the
 * content is known; the rest of the app (sign-in, module and permission
 * gates) is the real stack.
 */

const PAGES = '/attack-surface/pages'
const now = new Date().toISOString()
const hostile = 'https://skimmer.example.net/c.js?<img src=x onerror=alert(1)>'

async function stubPageMonitoring(page: Page) {
  await page.route(
    (url) => url.pathname.startsWith('/api/v1/easm/page-monitoring/'),
    (route) => {
      const path = new URL(route.request().url()).pathname
      const json = (body: unknown) =>
        route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
      const change = {
        id: 'c1',
        watch_id: 'w1',
        asset_id: 'a1',
        url: 'https://shop.example.com/login',
        detected_at: now,
        severity: 'high',
        muted: false,
        summary: {
          scripts_added: 1,
          scripts_removed: 0,
          third_party_added: 1,
          new_third_party_hosts: 1,
          content_changed: false,
          urls_added: 0,
          urls_removed: 0,
          lines_added: 0,
          lines_removed: 0,
        },
      }
      if (path.endsWith('/changes/c1'))
        return json({
          ...change,
          diff: {
            kind: 'html',
            size_from: 1,
            size_to: 2,
            new_third_party_hosts: ['skimmer.example.net'],
            scripts_added: [
              { id: 's', src: hostile, host: 'skimmer.example.net', third_party: true },
            ],
          },
        })
      if (path.endsWith('/changes')) return json({ items: [change], total: 1 })
      if (path.endsWith('/watches'))
        return json({
          max: 200,
          items: [
            {
              id: 'w1',
              asset_id: 'a1',
              url: 'https://shop.example.com/login',
              mode: 'js',
              source: 'manual',
              enabled: true,
              cadence_hours: 24,
              ignore_patterns: [],
              dynamic: false,
              state: 'ok',
              next_due_at: now,
              last_fetched_at: now,
              changes: 1,
              scripts: 1,
              created_at: now,
              updated_at: now,
            },
          ],
        })
      if (path.endsWith('/suggestions')) return json({ items: [] })
      return route.fulfill({ status: 404, body: '{}' })
    }
  )
}

for (const vp of [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'phone', width: 390, height: 844 },
]) {
  test(
    `page changes and the diff on a ${vp.name}`,
    { tag: ['@attack-surface'] },
    async ({ page }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height })
      await stubPageMonitoring(page)
      await page.goto(PAGES)
      const tabs = page.getByRole('navigation', { name: 'Attack surface sections' })
      await expect(tabs).toBeVisible({ timeout: 30_000 })
      await expect(page.getByRole('heading', { name: 'Watched pages' })).toBeVisible()
      await expect(page.getByTestId('page-watch')).toHaveCount(1)
      // No sideways scroll at this width.
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth
      )
      expect(overflow).toBeLessThanOrEqual(1)

      await page.getByRole('button', { name: /Open the change of/ }).click()
      const sheet = page.getByTestId('page-change-sheet')
      await expect(sheet).toBeVisible()
      await expect(sheet.getByTestId('diff-new-hosts')).toContainText('skimmer.example.net')
      await expect(sheet.getByTestId('diff-scripts-added')).toContainText(
        '<img src=x onerror=alert(1)>'
      )
      await expect(sheet.locator('img')).toHaveCount(0)
    }
  )
}
