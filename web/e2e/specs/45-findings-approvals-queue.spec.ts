import type { Browser, Locator, Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { getE2EConfig } from '../helpers/env'
import { loginAs } from '../helpers/auth'

/**
 * Approval requests (/findings/approvals) against real requests: the spec
 * asks for false positives through the API, as a second person (the seeded
 * member) and as the signed-in owner, then decides them on the page.
 *
 * - Another person's request: Approve (confirm, then the decision is said in
 *   the page's status region) and Reject (a reason is required first).
 * - The owner's own request: no decision controls (the four-eyes rule), "Your
 *   request" with its reason; Remind approvers once, a second reminder within
 *   the hour is refused; Cancel request after its confirm.
 */

interface Created {
  id: string
  findingId: string
  title: string
  note: string
}

/** Same-origin fetch from the page, with the CSRF pair the proxy checks. */
async function apiCall<T>(
  page: Page,
  method: 'GET' | 'POST',
  url: string,
  body?: unknown
): Promise<{ status: number; body: T }> {
  return page.evaluate(
    async ({ method, url, body }) => {
      const csrf = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/)?.[1] ?? ''
      const res = await fetch(url, {
        method,
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': decodeURIComponent(csrf) },
        body: body === undefined ? undefined : JSON.stringify(body),
      })
      const text = await res.text()
      return { status: res.status, body: (text ? JSON.parse(text) : null) as T }
    },
    { method, url, body }
  )
}

interface FreeFinding {
  id: string
  title?: string
  asset_id: string
}

/**
 * `count` open findings that have no pending request, taken from the end of
 * the list so specs that take the first one (39-my-work) do not race for the
 * same finding.
 */
async function freeFindings(page: Page, count: number): Promise<FreeFinding[]> {
  const list = await apiCall<{ data?: FreeFinding[] }>(
    page,
    'GET',
    '/api/v1/findings?status=new,confirmed&pending_approval=false&per_page=50'
  )
  expect(list.status, 'list open findings').toBe(200)
  const free = (list.body.data ?? []).slice(-count)
  expect(free.length, 'open findings without a pending request').toBe(count)
  return free
}

/** Asks for a false positive on each finding, as the person signed in on `page`. */
async function requestFalsePositives(
  page: Page,
  findings: FreeFinding[],
  tag: string
): Promise<Created[]> {
  const out: Created[] = []
  for (const [i, f] of findings.entries()) {
    const note = `E2E queue ${tag} ${i} ${Date.now()}`
    const res = await apiCall<{ id: string }>(page, 'POST', `/api/v1/findings/${f.id}/approvals/`, {
      requested_status: 'false_positive',
      closure_reason: 'detection_error',
      justification: note,
    })
    expect(res.status, `request on ${f.id}`).toBe(201)
    out.push({ id: res.body.id, findingId: f.id, title: f.title ?? '', note })
  }
  return out
}

/**
 * Lets the member see the findings: a member sees only the assets in their
 * data scope, so the owner grants them each finding's asset.
 */
async function grantAssets(owner: Page, member: Page, findings: FreeFinding[]) {
  const me = await apiCall<{ id: string }>(member, 'GET', '/api/v1/users/me')
  expect(me.status, 'member profile').toBe(200)
  for (const assetId of new Set(findings.map((f) => f.asset_id))) {
    const res = await apiCall(owner, 'POST', `/api/v1/assets/${assetId}/access-grants/`, {
      user_id: me.body.id,
    })
    expect([201, 409], `grant on ${assetId}`).toContain(res.status)
  }
}

/** A page signed in as the seeded member, or null when the seed has none. */
async function memberPage(browser: Browser): Promise<Page | null> {
  const cfg = getE2EConfig()
  const email = process.env.E2E_LIMITED_EMAIL
  const password = process.env.E2E_LIMITED_PASSWORD
  if (!cfg.ok || !email || !password) return null
  // An empty session: a new context otherwise starts from the worker's saved
  // (owner) session, and /login sends it straight to the dashboard.
  const context = await browser.newContext({
    baseURL: cfg.config.baseURL,
    storageState: { cookies: [], origins: [] },
  })
  const page = await context.newPage()
  await loginAs(page, { ...cfg.config, userEmail: email, userPassword: password })
  return page
}

function rowOf(page: Page, note: string): Locator {
  return page.getByRole('row').filter({ hasText: note })
}

const announcer = (page: Page) => page.locator('[data-slot="queue-announcer"]')

/**
 * Confirms a sensitive decision. The API asks for a recent sign-in: when the
 * worker's session is older than the window, the page asks for the password
 * first.
 */
async function confirmWithStepUp(page: Page, confirm: Locator) {
  await confirm.click()
  const cfg = getE2EConfig()
  const password = page.getByRole('dialog').getByLabel(/password/i)
  if (cfg.ok && (await password.isVisible({ timeout: 2_000 }).catch(() => false))) {
    await password.fill(cfg.config.userPassword)
    await page
      .getByRole('dialog')
      .getByRole('button', { name: /confirm|verify|continue/i })
      .click()
  }
}

test.describe('approval requests decide real requests', () => {
  test.describe.configure({ mode: 'serial' })

  test(
    "another person's request: approve after the confirm, reject with a reason",
    { tag: ['@findings'] },
    async ({ page, browser }) => {
      const member = await memberPage(browser)
      test.skip(!member, 'Set E2E_LIMITED_EMAIL / E2E_LIMITED_PASSWORD')
      await page.setViewportSize({ width: 1440, height: 900 })
      await page.goto('/findings/approvals')
      const findings = await freeFindings(page, 2)
      await grantAssets(page, member!, findings)
      const [toApprove, toReject] = await requestFalsePositives(member!, findings, 'other')
      await member!.context().close()

      await page.reload()
      await expect(page.getByRole('heading', { level: 1, name: 'Approval requests' })).toBeVisible()

      // Approve: the row's own button opens the confirm; the outcome is said.
      const approveRow = rowOf(page, toApprove.note)
      await expect(approveRow).toBeVisible()
      await expect(approveRow.locator('[data-slot="queue-own-request"]')).toHaveCount(0)
      await approveRow.locator('[data-slot="queue-approve"]').click()
      const confirm = page.getByRole('alertdialog')
      await expect(confirm).toContainText('Approve this status change?')
      await confirmWithStepUp(page, confirm.getByRole('button', { name: 'Approve' }))
      await expect(announcer(page)).toHaveText(
        /Approval request approved|Your approval is recorded/
      )
      await expect(rowOf(page, toApprove.note)).toHaveCount(0)

      // Reject: the reason is required before the decision can be sent.
      const rejectRow = rowOf(page, toReject.note)
      await rejectRow.locator('[data-slot="queue-reject"]').click()
      const dialog = page.getByRole('dialog').filter({ hasText: 'Reject request' })
      const send = dialog.getByRole('button', { name: 'Reject', exact: true })
      await expect(send).toBeDisabled()
      await dialog.getByRole('textbox').fill('E2E: the scanner was right, this is exploitable.')
      await expect(send).toBeEnabled()
      await send.click()
      await expect(announcer(page)).toHaveText(/Approval request rejected/)
      await expect(rowOf(page, toReject.note)).toHaveCount(0)

      // Both decisions are recorded on the server.
      const decided = await apiCall<{ data: Array<{ id: string; status: string }> }>(
        page,
        'GET',
        '/api/v1/approvals?per_page=100'
      )
      const statusOf = (id: string) => decided.body.data.find((a) => a.id === id)?.status
      expect(statusOf(toApprove.id)).toBe('approved')
      expect(statusOf(toReject.id)).toBe('rejected')

      // The Rejected lens lists the rejected request with no decision controls.
      await page.goto('/findings/approvals?status=rejected')
      const rejected = rowOf(page, toReject.note)
      await expect(rejected).toBeVisible()
      await expect(rejected.locator('[data-slot="queue-decision-actions"]')).toHaveCount(0)
    }
  )

  test(
    'your own request: no decision, remind once an hour, cancel after the confirm',
    { tag: ['@findings'] },
    async ({ page }) => {
      await page.setViewportSize({ width: 1440, height: 900 })
      await page.goto('/findings/approvals')
      const [mine] = await requestFalsePositives(page, await freeFindings(page, 1), 'own')
      await page.reload()

      const row = rowOf(page, mine.note)
      await expect(row).toBeVisible()
      // The four-eyes rule: no Approve or Reject on your own request, and the
      // reason is in the accessible text, not only in a tooltip.
      await expect(row.locator('[data-slot="queue-approve"]')).toHaveCount(0)
      await expect(row.locator('[data-slot="queue-reject"]')).toHaveCount(0)
      const own = row.locator('[data-slot="queue-own-request"]')
      await expect(own).toContainText('Your request')
      await expect(own).toContainText('Another approver must decide your own request.')

      const more = row.getByRole('button', { name: /^Actions for / })

      // Remind: once after the confirm; a second reminder within the hour is refused.
      await more.click()
      await page.getByRole('menuitem', { name: 'Remind approvers' }).click()
      await page.getByRole('alertdialog').getByRole('button', { name: 'Send reminder' }).click()
      await expect(announcer(page)).toHaveText(/Reminded \d+ approver/)
      await more.click()
      await page.getByRole('menuitem', { name: 'Remind approvers' }).click()
      await page.getByRole('alertdialog').getByRole('button', { name: 'Send reminder' }).click()
      await expect(announcer(page)).toHaveText(/already reminded in the last hour/)

      // Cancel: Keep request is the safe answer; Cancel request withdraws it.
      await more.click()
      await page.getByRole('menuitem', { name: 'Cancel request' }).click()
      const cancel = page.getByRole('alertdialog')
      await expect(cancel.getByRole('button', { name: 'Keep request' })).toBeFocused()
      await cancel.getByRole('button', { name: 'Cancel request' }).click()
      await expect(announcer(page)).toHaveText(/Approval request canceled/)
      await expect(rowOf(page, mine.note)).toHaveCount(0)

      const after = await apiCall<{ data: Array<{ id: string; status: string }> }>(
        page,
        'GET',
        '/api/v1/approvals?per_page=100'
      )
      expect(after.body.data.find((a) => a.id === mine.id)?.status).toBe('canceled')
    }
  )
})
