import { test, expect } from '../fixtures/authenticated-page'
import type { Locator, Page } from '@playwright/test'

/**
 * New Scan, Targets step, at a phone (390px) and a desktop (1440px) width:
 * the input comes first, then one readiness line and the refused targets
 * grouped by reason with the server's ranked fixes; the footer is one row
 * (Back on the left, Next on the right) and Next is disabled with its
 * reason while nothing can run. The scope check is answered by a route
 * mock, so the spec does not depend on the organization's scope.
 */

const DRAFT_PREFIX = 'openctem:new-scan-draft:'

const BLOCKED = {
  tier: 1,
  routing: { preference: 'platform', runs_on: 'platform', reason: 'platform_sensors' },
  results: [
    {
      target: 'www.acme-e2e.example',
      allowed: false,
      code: 'proof_required',
      message: 'Platform sensors need a verified domain of your organization.',
      remedies: [
        { action: 'run_on_tenant_sensor' },
        { action: 'verify_domain', domain: 'acme-e2e.example' },
        { action: 'remove' },
      ],
    },
  ],
}

async function openTargetsStep(page: Page): Promise<Locator> {
  await page.route('**/api/v1/scope/check', (route) =>
    route.fulfill({ json: BLOCKED, headers: { 'content-type': 'application/json' } })
  )
  await page.goto('/scans')
  const open = page.getByRole('button', { name: /new scan/i }).first()
  await expect(open).toBeVisible({ timeout: 20_000 })
  await open.click()
  let dialog = page.getByRole('dialog', { name: /new scan/i })
  await dialog
    .getByLabel(/scan name/i)
    .first()
    .fill('Targets step check')
  const key = await page.waitForFunction(
    (prefix) => Object.keys(sessionStorage).find((k) => k.startsWith(prefix)) ?? null,
    DRAFT_PREFIX
  )
  const draftKey = (await key.jsonValue()) as string
  await page.evaluate((k) => {
    const draft = JSON.parse(sessionStorage.getItem(k) ?? '{}')
    draft.step = 'targets'
    draft.form = {
      ...draft.form,
      name: 'Targets step check',
      scannerName: draft.form?.scannerName || 'nuclei',
      sensorPreference: 'platform',
      targets: { ...(draft.form?.targets ?? {}), customTargets: ['www.acme-e2e.example'] },
    }
    sessionStorage.setItem(k, JSON.stringify(draft))
  }, draftKey)
  await page.reload()
  await page
    .getByRole('button', { name: /new scan/i })
    .first()
    .click()
  dialog = page.getByRole('dialog', { name: /new scan/i })
  await expect(dialog.getByTestId('readiness-line')).toContainText('1 blocked', {
    timeout: 15_000,
  })
  return dialog
}

for (const width of [390, 1440]) {
  test(`Targets step reads in order and gates Next (${width}px)`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: width < 768 ? 844 : 900 })
    const dialog = await openTargetsStep(page)

    // Input first, result second.
    const field = dialog.getByTestId('target-chips-field')
    const result = dialog.getByTestId('targets-result')
    const fieldBox = (await field.boundingBox())!
    const resultBox = (await result.boundingBox())!
    if (width < 768) expect(resultBox.y).toBeGreaterThan(fieldBox.y)
    else expect(resultBox.x).toBeGreaterThan(fieldBox.x)

    // The chip's remove button: a 44px tap area (32px plus the hit extension).
    const remove = field.getByRole('button', { name: /^remove /i }).first()
    expect((await remove.boundingBox())!.height).toBeGreaterThanOrEqual(32)

    // Ranked fixes, the first primary.
    const fixes = dialog.getByTestId('refusal-remedies').getByRole('button')
    await expect(fixes.first()).toHaveText(/run on my sensor/i)
    await expect(fixes.nth(1)).toHaveText(/verify acme-e2e\.example/i)

    // One footer row: Back left, Next right, disabled with its reason; no Cancel.
    const back = dialog.getByTestId('wizard-back')
    const next = dialog.getByTestId('wizard-next')
    await expect(next).toBeDisabled()
    await expect(dialog.getByTestId('wizard-note')).toHaveText(/blocked target/i)
    const b = (await back.boundingBox())!
    const n = (await next.boundingBox())!
    expect(Math.abs(b.y - n.y)).toBeLessThan(4)
    expect(n.x).toBeGreaterThan(b.x)
    await expect(dialog.getByRole('button', { name: /^cancel$/i })).toHaveCount(0)

    if (width < 768) {
      await expect(dialog.getByTestId('stepper-phone')).toHaveText(/step 2 of 5: targets/i)
    }

    const body = dialog.locator('[data-slot="dialog-body"]')
    const box = await body.evaluate((el) => ({ scroll: el.scrollWidth, client: el.clientWidth }))
    expect(box.scroll, 'targets body scrolls sideways').toBeLessThanOrEqual(box.client + 1)
    await info.attach(`targets-${width}`, {
      body: await page.screenshot(),
      contentType: 'image/png',
    })

    // Run on my sensor switches the preference: the check runs again.
    const rechecked = page.waitForRequest(
      (r) =>
        r.url().includes('/api/v1/scope/check') &&
        (r.postDataJSON() as { sensor_preference?: string }).sensor_preference === 'tenant'
    )
    await fixes.first().click()
    await rechecked
  })
}
