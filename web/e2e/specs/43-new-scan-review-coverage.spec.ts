import path from 'path'
import type { Locator, Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * New Scan review, "What this scan covers" (research/277): how many targets
 * the scan takes and every skipped target grouped by reason, at 1440px and
 * 390px. Skipping is an outcome, not a failure: nothing in the block is red,
 * an expected reason (names with no DNS answer) is neutral, the names open
 * behind a disclosure with a search, nothing scrolls sideways and axe finds
 * no serious violation. The preview answer is fixed (the API's own tests
 * cover how it is computed), so the spec does not depend on DNS or seed data.
 */

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')
const DRAFT_PREFIX = 'openctem:new-scan-draft:'

interface AxeResult {
  violations: Array<{ id: string; impact: string | null; nodes: Array<{ target: string[] }> }>
}

const gone = Array.from({ length: 30 }, (_, i) => `old${i}.example.com`)
const PREVIEW = {
  zones_enabled: false,
  routed: false,
  resolved_targets: 121,
  excluded_targets: 1,
  excluded: ['legacy.example.com'],
  targets: [],
  zones: [],
  unzoned_targets: 0,
  uncovered_targets: 0,
  jobs: 13,
  targets_per_job: 10,
  warnings: [],
  will_scan: 121,
  skipped_total: 435,
  skipped: [
    { reason: 'not_resolving', tone: 'info', count: 434, targets: gone },
    { reason: 'excluded', tone: 'info', count: 1, targets: ['legacy.example.com'] },
  ],
}

async function openReview(page: Page): Promise<Locator> {
  await page.route('**/api/v1/scan-zones/preview', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(PREVIEW) })
  )
  await page.goto('/scans')
  const open = page.getByRole('button', { name: /new scan/i }).first()
  await expect(open).toBeVisible({ timeout: 20_000 })
  await open.click()
  let dialog = page.getByRole('dialog', { name: /new scan/i })
  await dialog
    .getByLabel(/scan name/i)
    .first()
    .fill('Coverage check')
  const key = await page.waitForFunction(
    (prefix) => Object.keys(sessionStorage).find((k) => k.startsWith(prefix)) ?? null,
    DRAFT_PREFIX
  )
  const draftKey = (await key.jsonValue()) as string
  await page.evaluate((k) => {
    const draft = JSON.parse(sessionStorage.getItem(k) ?? '{}')
    draft.step = 'review'
    draft.form = {
      ...draft.form,
      name: 'Coverage check',
      scannerName: draft.form?.scannerName || 'nuclei',
      targets: { ...(draft.form?.targets ?? {}), customTargets: ['*.example.com'] },
    }
    sessionStorage.setItem(k, JSON.stringify(draft))
  }, draftKey)
  await page.reload()
  await page
    .getByRole('button', { name: /new scan/i })
    .first()
    .click()
  dialog = page.getByRole('dialog', { name: /new scan/i })
  await expect(dialog).toBeVisible()
  return dialog
}

for (const width of [1440, 390]) {
  test(`New Scan review shows skipped targets by reason, never red (${width}px)`, async ({
    page,
  }, info) => {
    await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })
    const dialog = await openReview(page)
    const section = dialog.getByTestId('new-scan-routing')
    test.skip(
      (await section.count()) === 0,
      'the signed-in user cannot read scan zones, so the preview is hidden'
    )
    await expect(section.getByTestId('outcome-will-scan')).toHaveText('121', { timeout: 15_000 })
    await expect(section.getByTestId('outcome-skipped')).toHaveText('435')
    expect(await section.locator('.text-destructive').count(), 'red inside the block').toBe(0)
    // No zones: no zone wording at all.
    await expect(section.getByText(/zone/i)).toHaveCount(0)

    const group = section.locator('li[data-reason="not_resolving"]')
    await expect(group).toHaveAttribute('data-tone', 'info')
    const trigger = group.getByRole('button', { expanded: false })
    await trigger.focus()
    await page.keyboard.press('Enter')
    await expect(group.getByRole('button', { expanded: true })).toBeVisible()
    await expect(group.getByTestId('skip-names').getByRole('listitem')).toHaveCount(30)
    await expect(group.getByText(/and 404 more not listed/)).toBeVisible()
    await group.getByRole('searchbox').fill('old2')
    // old2, old20..old29
    await expect(group.getByTestId('skip-names').getByRole('listitem')).toHaveCount(11)

    const body = dialog.locator('[data-slot="dialog-body"]')
    const box = await body.evaluate((el) => ({ scroll: el.scrollWidth, client: el.clientWidth }))
    expect(box.scroll, 'review body scrolls sideways').toBeLessThanOrEqual(box.client + 1)

    await page.addScriptTag({ path: AXE })
    const result = (await page.evaluate(async () => {
      const w = window as unknown as {
        axe: { run: (ctx: unknown, opts: unknown) => Promise<AxeResult> }
      }
      return w.axe.run(
        { include: [['[data-testid="new-scan-routing"]']] },
        { resultTypes: ['violations'] }
      )
    })) as AxeResult
    const serious = result.violations
      .filter((v) => v.impact === 'serious' || v.impact === 'critical')
      .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
    expect(serious).toEqual([])

    await info.attach(`review-coverage-${width}.png`, {
      body: await section.screenshot(),
      contentType: 'image/png',
    })
  })
}
