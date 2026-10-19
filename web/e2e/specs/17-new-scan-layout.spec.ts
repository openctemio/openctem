import { test, expect } from '../fixtures/authenticated-page'
import type { Locator, Page, TestInfo } from '@playwright/test'

/**
 * New Scan wizard layout: no step may scroll sideways. A fieldset is
 * min-content wide by default, so one long truncated line (the names a
 * wildcard target matched) once made the Targets step body scroll
 * horizontally, clipped asset names and radio labels on the left and left
 * the sticky summary bar narrower than the body.
 *
 * Every step is opened at a phone, a tablet and a desktop width with long
 * typed targets (the wizard restores its draft from sessionStorage), and the
 * dialog body must not be wider than its box. Screenshots are attached.
 */

const WIDTHS = [360, 768, 1280]
const STEPS = ['basic', 'targets', 'options', 'schedule', 'review'] as const
const DRAFT_PREFIX = 'openctem:new-scan-draft:'

// Long names, a wildcard and a long URL: the content that overflowed.
const LONG_TARGETS = [
  '*.example.com',
  '*.www.manhnv.com',
  '*.example.com',
  'a-very-long-subdomain-name-that-keeps-going-and-going.department.example.com',
  'https://portal.example.com/a/very/long/path/that/should/wrap/or/truncate?with=query&and=more',
  'a-very-long-support-center-label-for-a-branch-office.example.com',
]

async function openNewScan(page: Page): Promise<Locator> {
  await page.goto('/scans')
  const open = page.getByRole('button', { name: /new scan/i }).first()
  await expect(open).toBeVisible({ timeout: 20_000 })
  await open.click()
  const dialog = page.getByRole('dialog', { name: /new scan/i })
  await expect(dialog).toBeVisible()
  await dialog.evaluate((el) => Promise.all(el.getAnimations().map((a) => a.finished)))
  return dialog
}

async function shot(page: Page, info: TestInfo, name: string) {
  await info.attach(name, { body: await page.screenshot(), contentType: 'image/png' })
}

for (const width of WIDTHS) {
  test(`New Scan never scrolls sideways (${width}px)`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 })
    let dialog = await openNewScan(page)
    // Typing the name stores the draft; its key carries the organization.
    await dialog
      .getByLabel(/scan name/i)
      .first()
      .fill('Layout check')
    const key = await page.waitForFunction(
      (prefix) => Object.keys(sessionStorage).find((k) => k.startsWith(prefix)) ?? null,
      DRAFT_PREFIX
    )
    const draftKey = (await key.jsonValue()) as string
    expect(draftKey).toBeTruthy()

    for (const step of STEPS) {
      await page.evaluate(
        ({ k, s, targets }) => {
          const draft = JSON.parse(sessionStorage.getItem(k) ?? '{}')
          draft.step = s
          draft.form = {
            ...draft.form,
            name: 'Layout check',
            scannerName: draft.form?.scannerName || 'nuclei',
            targets: {
              ...(draft.form?.targets ?? {}),
              customTargets: targets,
              coverage: 'subdomains',
            },
          }
          sessionStorage.setItem(k, JSON.stringify(draft))
        },
        { k: draftKey, s: step, targets: LONG_TARGETS }
      )
      await page.reload()
      dialog = await openNewScan(page)
      const body = dialog.locator('[data-slot="dialog-body"]')
      await expect(body).toBeVisible()
      await page.waitForLoadState('networkidle')
      await shot(page, info, `${width}-${step}`)
      const box = await body.evaluate((el) => ({ scroll: el.scrollWidth, client: el.clientWidth }))
      expect(box.scroll, `${step} body scrolls sideways at ${width}px`).toBeLessThanOrEqual(
        box.client + 1
      )
      const dialogBox = await dialog.evaluate((el) => ({
        scroll: el.scrollWidth,
        client: el.clientWidth,
      }))
      expect(dialogBox.scroll, `${step} dialog scrolls sideways at ${width}px`).toBeLessThanOrEqual(
        dialogBox.client + 1
      )
    }
  })
}
