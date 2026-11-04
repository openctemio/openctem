import { test, expect } from '../fixtures/authenticated-page'
import type { Locator, Page } from '@playwright/test'

/**
 * New Scan at a phone (390x844) and a desktop (1440x900) size: every step
 * can be opened before the earlier ones are complete, the live summary is
 * beside the step (desktop) or in a bar above the footer (phone), a pasted
 * list is analysed before it is added (kinds, entries not added with the
 * reason), and Create stays disabled with the first problem named as a link
 * to its step. The scope check is answered by a route mock, so the spec does
 * not depend on the organization's scope. Design: research/418.
 */

const IN_SCOPE = (targets: string[]) => ({
  tier: 1,
  routing: { preference: 'auto', runs_on: 'tenant', reason: 'tenant_first' },
  results: targets.map((target) => ({
    target,
    allowed: true,
    via: { kind: 'rule', pattern: '*.acme-e2e.example' },
  })),
})

async function openNewScan(page: Page): Promise<Locator> {
  await page.route('**/api/v1/scope/check', async (route) => {
    const body = (route.request().postDataJSON() ?? {}) as { targets?: string[] }
    await route.fulfill({
      json: IN_SCOPE(body.targets ?? []),
      headers: { 'content-type': 'application/json' },
    })
  })
  await page.goto('/scans')
  const open = page.getByRole('button', { name: /new scan/i }).first()
  await expect(open).toBeVisible({ timeout: 20_000 })
  await open.click()
  const dialog = page.getByRole('dialog', { name: /new scan/i })
  await expect(dialog).toBeVisible()
  await dialog.evaluate((el) => Promise.all(el.getAnimations().map((a) => a.finished)))
  return dialog
}

/** A step button: the desktop stepper, or the phone step list (opened first). */
async function openStep(dialog: Locator, width: number, name: RegExp) {
  if (width < 640) {
    await dialog.getByTestId('stepper-phone').click()
    await dialog.locator('#scan-stepper-list').getByRole('button', { name }).click()
  } else {
    await dialog.getByRole('navigation', { name: 'Steps' }).getByRole('button', { name }).click()
  }
}

for (const width of [390, 1440]) {
  test(
    `New Scan: any step opens, live summary, bulk paste, gated Create (${width}px)`,
    { tag: ['@scans'] },
    async ({ page }, info) => {
      await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })
      const dialog = await openNewScan(page)

      // Jump straight to Review with nothing filled in: it opens.
      await openStep(dialog, width, /^Review/)
      await expect(dialog.getByTestId('wizard-step-heading')).toHaveText(/step 5 of 5: review/i)
      const create = dialog.getByTestId('wizard-create')
      await expect(create).toBeDisabled()
      const fix = dialog.getByTestId('wizard-fix-link')
      await expect(fix).toBeVisible()

      // The link goes to the first problem (the name, on What).
      await fix.click()
      await expect(dialog.getByTestId('wizard-step-heading')).toHaveText(/step 1 of 5: what/i)
      await dialog
        .getByLabel(/scan name/i)
        .first()
        .fill('Free navigation check')

      // Targets: paste a list, see it analysed before it is added.
      await openStep(dialog, width, /^Targets/)
      await dialog.getByTestId('bulk-open').click()
      const panel = dialog.getByTestId('bulk-panel')
      await panel
        .getByRole('textbox')
        .first()
        .fill(
          [
            'a.acme-e2e.example',
            'b.acme-e2e.example, c.acme-e2e.example',
            'A.acme-e2e.example.',
            '203.0.113.0/24',
            '10.0.0.0/8',
            '# a comment',
          ].join('\n')
        )
      await expect(panel.getByTestId('paste-counts')).toContainText('4 targets')
      await expect(panel.getByTestId('paste-invalid-list')).toContainText('10.0.0.0/8')
      await panel.getByRole('button', { name: 'Remove all' }).click()
      await panel.getByTestId('bulk-add').click()
      await expect(dialog.getByTestId('kind-counts')).toContainText('4 typed targets')

      // The summary says it on every step.
      if (width < 1024) {
        await expect(dialog.getByTestId('summary-bar')).toContainText('4 targets')
      } else {
        await expect(dialog.getByRole('complementary', { name: 'Summary' })).toContainText(
          '4 targets'
        )
      }

      // Nothing stops Next; the footer stays one row.
      const next = dialog.getByTestId('wizard-next')
      await expect(next).toBeEnabled()
      const back = dialog.getByTestId('wizard-back')
      const b = (await back.boundingBox())!
      const n = (await next.boundingBox())!
      expect(Math.abs(b.y - n.y)).toBeLessThan(4)

      const body = dialog.locator('[data-slot="dialog-body"]')
      const box = await body.evaluate((el) => ({ scroll: el.scrollWidth, client: el.clientWidth }))
      expect(box.scroll, 'body scrolls sideways').toBeLessThanOrEqual(box.client + 1)
      await info.attach(`new-scan-targets-${width}`, {
        body: await page.screenshot(),
        contentType: 'image/png',
      })

      await openStep(dialog, width, /^Schedule/)
      await expect(dialog.getByTestId('wizard-step-heading')).toHaveText(/step 4 of 5: schedule/i)
      await info.attach(`new-scan-schedule-${width}`, {
        body: await page.screenshot(),
        contentType: 'image/png',
      })
    }
  )
}
