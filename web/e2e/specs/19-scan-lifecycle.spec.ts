import { test, expect } from '../fixtures/authenticated-page'
import type { Page } from '@playwright/test'

/**
 * A scan's life in the console: create it in the New Scan wizard, edit it
 * (name, targets, max duration) in the Edit wizard, run it from its page and
 * open the run, for a single-scanner scan and a workflow scan.
 *
 * Regressions this guards:
 *   1. Edit dropped a target change and still said "updated" (the update
 *      API had no target fields).
 *   2. The max duration field turned 3600 into 30600 while typing.
 *   3. The scan page had no Edit at all.
 *
 * Each run creates its own scope entries and assets (unique names under
 * example.com), so it needs only an owner account; a sensor with nuclei
 * lets the run start (without one the run is still recorded and opened).
 */

const DRAFT_PREFIX = 'openctem:new-scan-draft:'

/**
 * A write through the web's /api/v1 proxy, from the page: the console's
 * fetch adds the CSRF header and the request is same-origin, as the proxy
 * requires.
 */
async function apiWrite(page: Page, method: 'POST' | 'PUT', path: string, data: unknown) {
  const res = await page.evaluate(
    async ({ method, path, data }) => {
      const r = await fetch(path, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })
      return { status: r.status, body: await r.text() }
    },
    { method, path, data }
  )
  expect(res.status, `${method} ${path}: ${res.status} ${res.body}`).toBeLessThan(300)
  return JSON.parse(res.body)
}

/** Scope entries and inventory assets for the hosts, so the scan may scan them. */
async function allowHosts(page: Page, hosts: string[]) {
  for (const host of hosts) {
    await apiWrite(page, 'POST', '/api/v1/scope/targets', {
      target_type: 'domain',
      pattern: host,
      description: 'e2e scan lifecycle',
    })
    await apiWrite(page, 'POST', '/api/v1/assets', {
      name: host,
      type: 'domain',
      criticality: 'low',
    })
  }
}

/** Opens New Scan on its Review step with the form given (the wizard's draft). */
async function createInWizard(page: Page, form: Record<string, unknown>) {
  await page.goto('/scans')
  const open = page.getByRole('button', { name: /new scan/i }).first()
  await expect(open).toBeEnabled({ timeout: 30_000 })
  await open.click()
  let dialog = page.getByRole('dialog', { name: /new scan/i })
  await dialog
    .getByLabel(/scan name/i)
    .first()
    .fill(String(form.name))
  const key = await page.waitForFunction(
    (prefix) => Object.keys(sessionStorage).find((k) => k.startsWith(prefix)) ?? null,
    DRAFT_PREFIX
  )
  await page.evaluate(
    ({ k, f }) => {
      const draft = JSON.parse(sessionStorage.getItem(k) ?? '{}')
      draft.step = 'review'
      draft.form = { ...draft.form, ...f }
      sessionStorage.setItem(k, JSON.stringify(draft))
    },
    { k: (await key.jsonValue()) as string, f: form }
  )
  await page.reload()
  await page
    .getByRole('button', { name: /new scan/i })
    .first()
    .click()
  dialog = page.getByRole('dialog', { name: /new scan/i })
  const created = page.waitForResponse(
    (r) =>
      r.request().method() === 'POST' &&
      new URL(r.url()).pathname.replace(/\/$/, '') === '/api/v1/scans'
  )
  await dialog.getByRole('button', { name: /^save scan$/i }).click()
  const res = await created
  expect(res.status(), await res.text()).toBe(201)
  return (await res.json()) as { id: string }
}

async function editOnScanPage(page: Page, scanId: string, name: string, targets: string[]) {
  await page.goto(`/scans/${scanId}`)
  await page.getByRole('button', { name: /^edit$/i }).click()
  const dialog = page.getByRole('dialog', { name: /edit scan/i })
  await expect(dialog).toBeVisible()
  await dialog.getByLabel(/scan name/i).fill(name)
  await dialog.getByRole('button', { name: /^next/i }).click()
  // The targets field holds the saved targets as chips: remove them, then
  // type the new ones (a comma adds each).
  const field = dialog.getByTestId('target-chips-field')
  const removeChip = field.getByRole('button', { name: /^remove /i })
  while ((await removeChip.count()) > 0) await removeChip.first().click()
  await field.getByRole('textbox').fill(`${targets.join(', ')}, `)
  await dialog.getByRole('button', { name: /^next/i }).click()
  await dialog
    .getByText(/advanced/i)
    .first()
    .click()
  const maxDuration = dialog.locator('#timeout-seconds')
  await maxDuration.fill('')
  await maxDuration.pressSequentially('3600')
  await maxDuration.blur()
  await dialog.getByRole('button', { name: /^next/i }).click()
  const saved = page.waitForResponse(
    (r) => r.request().method() === 'PUT' && new URL(r.url()).pathname === `/api/v1/scans/${scanId}`
  )
  await dialog.getByRole('button', { name: /save changes/i }).click()
  const res = await saved
  expect(res.status(), await res.text()).toBe(200)
  const body = (await res.json()) as { name: string; targets: string[]; timeout_seconds?: number }
  expect(body.name).toBe(name)
  expect([...body.targets].sort()).toEqual([...targets].sort())
  expect(body.timeout_seconds).toBe(3600)
  await expect(dialog).toBeHidden()
  await expect(page.getByRole('heading', { name })).toBeVisible()
}

async function runAndOpen(page: Page, scanId: string) {
  const triggered = page.waitForResponse(
    (r) =>
      r.request().method() === 'POST' &&
      new URL(r.url()).pathname === `/api/v1/scans/${scanId}/trigger`
  )
  await page.getByRole('button', { name: /^run now$/i }).click()
  const confirm = page.getByRole('alertdialog')
  // The confirm dialog renders a moment after the click; wait for it
  // instead of checking once.
  if (
    await confirm.waitFor({ state: 'visible', timeout: 3000 }).then(
      () => true,
      () => false
    )
  ) {
    await confirm.getByRole('button').last().click()
  }
  const res = await triggered
  // Started, or refused and recorded as a blocked run (no sensor in reach):
  // either way the run is in the history.
  expect([200, 201, 400, 409], await res.text()).toContain(res.status())
  const runsTable = page.getByRole('table')
  const firstRun = runsTable.getByRole('row').nth(1)
  await expect(firstRun).toBeVisible({ timeout: 30_000 })
  await firstRun.click()
  const sheet = page.getByRole('dialog')
  await expect(sheet).toBeVisible()
  await expect(sheet.getByText(/timeline/i).first()).toBeVisible({ timeout: 30_000 })
}

for (const kind of ['single', 'workflow'] as const) {
  test(
    `a ${kind} scan: create, edit, run, view the run`,
    { tag: ['@scans', '@smoke'] },
    async ({ page }) => {
      test.setTimeout(240_000)
      const stamp = `${Date.now().toString(36)}-${kind}`
      const first = `scan-e2e-${stamp}.example.com`
      const second = `scan-e2e-${stamp}-b.example.com`
      await page.goto('/scans')
      await allowHosts(page, [first, second])

      const form: Record<string, unknown> = {
        name: `E2E ${kind} ${stamp}`,
        intensity: 'active',
        mode: kind,
        targets: {
          type: 'asset_groups',
          assetGroupIds: [],
          assetIds: [],
          assetNames: {},
          customTargets: [first],
        },
        schedule: {
          runImmediately: false,
          saveOnly: true,
          frequency: 'weekly',
          dayOfWeek: 1,
          time: '02:00',
        },
      }
      if (kind === 'single') {
        form.scannerName = 'nuclei'
      } else {
        const workflow = (await apiWrite(page, 'POST', '/api/v1/scan-workflows/', {
          name: `E2E workflow ${stamp}`,
          steps: [{ step_key: 'vuln', name: 'Vulnerability templates', tool: 'nuclei', order: 1 }],
        })) as { id: string }
        form.workflowId = workflow.id
      }

      const scan = await createInWizard(page, form)
      await editOnScanPage(page, scan.id, `E2E ${kind} ${stamp} edited`, [first, second])
      await runAndOpen(page, scan.id)
    }
  )
}
