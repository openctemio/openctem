import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Attack surface > Discovery: four stage cards with status, progress and the
 * auto-validation count; Run calls the stage command; Abort all asks first.
 * The API answers are stubbed so the spec does not start coverage runs on the
 * stack it runs against; the page, its route guard and the tab are real.
 */

const PAGE = '/attack-surface/discovery'

function overview() {
  const now = new Date().toISOString()
  const stage = (stage: string, status: string, extra: Record<string, unknown> = {}) => ({
    stage,
    status,
    progress_done: 1,
    progress_total: 4,
    progress_unit: status === 'running' ? 'tasks' : 'pairs',
    last_run_at: now,
    capabilities: [
      {
        capability: 'resolve.dns',
        pairs: 4,
        covered: 1,
        due_now: 0,
        queued: 0,
        failed: 0,
        blocked: 0,
        paused: 0,
      },
    ],
    ...extra,
  })
  return {
    generated_at: now,
    loop_enabled: true,
    coverage_enabled: true,
    pass_every_seconds: 60,
    daily_budget: 5000,
    budget_used: 12,
    auto_validation: { assets: 3 },
    stages: [
      stage('asset_discovery', 'running'),
      stage('exposure_scan', 'idle'),
      stage('validation_scoping', 'paused', { reason: 'tool_missing', auto_validated_assets: 3 }),
      stage('technology_discovery', 'failed'),
    ],
  }
}

async function stub(page: Page, calls: string[]) {
  await page.route(/\/api\/v1\/attack-surface\/discovery(\/.*)?(\?.*)?$/, (route) => {
    const req = route.request()
    if (req.method() === 'GET') {
      return route.fulfill({ contentType: 'application/json', body: JSON.stringify(overview()) })
    }
    calls.push(new URL(req.url()).pathname)
    const body = req.url().endsWith('/discovery/cancel')
      ? { canceled: 1, failed: 0 }
      : {
          started: ['exposure_scan'],
          skipped: [],
          capabilities: ['scan.ports'],
          pairs_made_due: 2,
          next_pass_within_seconds: 60,
        }
    return route.fulfill({
      status: req.url().endsWith('/discovery/cancel') ? 200 : 202,
      contentType: 'application/json',
      body: JSON.stringify(body),
    })
  })
}

for (const width of [1440, 390]) {
  test(`discovery stages at ${width}px`, { tag: ['@attack-surface'] }, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    const calls: string[] = []
    await stub(page, calls)
    await page.goto(PAGE)
    const cards = page.getByTestId(/^discovery-stage-/)
    await expect(cards).toHaveCount(4, { timeout: 30_000 })
    await expect(page.getByTestId('discovery-auto-validated')).toHaveText('3 assets')
    await expect(page.getByTestId('discovery-freshness')).toContainText('Updated')
    // No sideways scroll on a phone.
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - window.innerWidth
    )
    expect(overflow).toBeLessThanOrEqual(1)

    const run = page.getByRole('button', { name: 'Run Exposure scan' })
    if (await run.isDisabled()) test.skip(true, 'this account cannot run scans')
    await run.click()
    await expect
      .poll(() => calls)
      .toContain('/api/v1/attack-surface/discovery/stages/exposure_scan/run')

    await page.getByRole('button', { name: 'Abort all' }).click()
    const dialog = page.getByRole('alertdialog')
    await expect(dialog).toBeVisible()
    expect(calls).not.toContain('/api/v1/attack-surface/discovery/cancel')
    await dialog.getByRole('button', { name: 'Abort all' }).click()
    await expect.poll(() => calls).toContain('/api/v1/attack-surface/discovery/cancel')
  })
}
