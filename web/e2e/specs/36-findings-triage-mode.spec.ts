import path from 'path'
import type { Page, Request } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Findings triage mode (research/234 §5.2) on the seeded stack: a keys-only
 * session over the ten "E2E triage" findings (web/e2e/ci/seed.sh), then the
 * statuses and approval rows read back from the API. Also: moving on costs
 * at most two API calls, the decision panel is a labelled region with a
 * visible button per key and no serious accessibility violation, and Exit
 * returns to the list the session started from.
 *
 * The spec decides its findings, so a retry finds fewer than ten waiting and
 * skips instead of deciding other specs' data.
 */

const QUEUE = 'status=new&q=E2E+triage'
const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')

interface AxeResult {
  violations: Array<{ id: string; impact: string | null; nodes: Array<{ target: string[] }> }>
}

async function apiGet<T>(page: Page, url: string): Promise<{ status: number; body: T }> {
  return page.evaluate(async (u) => {
    const res = await fetch(u)
    return { status: res.status, body: await res.json().catch(() => null) }
  }, url)
}

interface ListBody {
  total: number
  data: Array<{ id: string; title: string; status: string }>
}

const isApi = (req: Request) => {
  const type = req.resourceType()
  return (type === 'fetch' || type === 'xhr') && new URL(req.url()).pathname.startsWith('/api/v1/')
}

const title = (page: Page) => page.locator('#triage-finding-title')

/** Presses a key with nothing focused, the way a person works the queue. */
async function key(page: Page, k: string) {
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur())
  await page.keyboard.press(k)
}

async function fillRequest(page: Page) {
  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  await dialog.locator('#closure-reason').click()
  await page.getByRole('option').first().click()
  await dialog.locator('#justification').fill('E2E triage: decided in triage mode for the spec.')
  await dialog.getByRole('button', { name: 'Review' }).click()
  await dialog
    .getByRole('button', { name: /Submit for Approval|Mark as false positive|Accept the risk/ })
    .click()
  await expect(dialog).toBeHidden()
}

test(
  'a keys-only triage session decides ten findings',
  { tag: ['@findings'] },
  async ({ page }) => {
    test.setTimeout(180_000)
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings?severity=high')
    const waiting = await apiGet<ListBody>(page, `/api/v1/findings?${QUEUE}&per_page=25`)
    test.skip(
      (waiting.body?.total ?? 0) < 10,
      'the triage findings were decided by an earlier attempt'
    )

    // Into triage from the list: Exit must come back to this list.
    await page.evaluate((q) => {
      sessionStorage.setItem(
        'openctem.findings.triage',
        JSON.stringify({
          v: 1,
          query: q,
          returnTo: '/findings?severity=high',
          fromList: true,
          items: [],
          index: 0,
          outcomes: {},
          total: 0,
          exhausted: false,
        })
      )
    }, new URLSearchParams(QUEUE).toString())
    await page.goto(`/findings/triage?${QUEUE}`)
    await expect(title(page)).toHaveText(/E2E triage/, { timeout: 30_000 })
    await expect(page.getByTestId('triage-position')).toHaveText(/^1 of 10$/)

    // The decision panel: a labelled region with a visible button per key.
    const region = page.getByRole('region', { name: 'Decision' })
    for (const name of [
      /^Confirm/,
      /^Request false positive/,
      /^Request risk acceptance/,
      /^Assign$/,
      /^Skip$/,
      /^Evidence$/,
      /^Full page$/,
      /^All keys$/,
    ]) {
      await expect(region.getByRole('button', { name })).toBeVisible()
    }
    await page.addScriptTag({ path: AXE })
    const axe = (await page.evaluate(async () => {
      const w = window as unknown as {
        axe: { run: (ctx: unknown, opts: unknown) => Promise<AxeResult> }
      }
      return w.axe.run({ include: [['main#content']] }, { resultTypes: ['violations'] })
    })) as AxeResult
    expect(
      axe.violations
        .filter((v) => v.impact === 'serious' || v.impact === 'critical')
        .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
    ).toEqual([])

    // What each finding got, by title.
    // `a` on a new finding: the lifecycle refuses acceptance before confirmation,
    // so no request opens and the finding is then confirmed. `u` walks the
    // previous decision back (the request is cancelled, the assignment
    // returned) and shows that finding again, which is then decided again.
    const plan = [
      'c',
      'c',
      'f',
      'u',
      'f',
      'c',
      's',
      'a-then-c',
      'o',
      'u',
      'o',
      'c',
      'c',
      'c',
    ] as const
    type Step = (typeof plan)[number]
    const decided: Record<string, Step> = {}
    const undone = new Set<string>()
    const perNext: number[] = []
    let lastTitle = ''
    for (let i = 0; i < plan.length; i++) {
      const current = (await title(page).textContent())?.trim() ?? ''
      expect(current).toMatch(/E2E triage/)
      const k = plan[i]
      if (k === 'u') {
        await key(page, 'u')
        await expect(title(page)).toHaveText(lastTitle, { timeout: 15_000 })
        undone.add(lastTitle)
        continue
      }
      decided[current] = k
      lastTitle = current
      // The reads moving on makes: the next finding, and a window now and then.
      const reads: string[] = []
      const onRequest = (req: Request) => {
        if (!isApi(req) || req.method() !== 'GET') return
        const p = new URL(req.url()).pathname
        if (/^\/api\/v1\/findings(\/[0-9a-f-]{36})?$/.test(p)) reads.push(p)
      }
      page.on('request', onRequest)
      if (k === 'f') {
        await key(page, k)
        await fillRequest(page)
      } else if (k === 'a-then-c') {
        // Wait for the lifecycle's answer to `a` before the next key.
        const refused = page.waitForResponse((r) => r.url().endsWith('/transitions'))
        await key(page, 'a')
        await refused
        await expect(
          page.getByRole('region', { name: 'Decision' }).getByRole('button', { name: /^Confirm/ })
        ).toBeEnabled()
        await expect(page.getByRole('dialog')).toHaveCount(0)
        await expect(title(page)).toHaveText(current)
        await key(page, 'c')
      } else if (k === 'o') {
        await key(page, 'o')
        await expect(page.getByRole('option').first()).toBeVisible()
        await page.keyboard.press('Enter')
      } else {
        await key(page, k)
      }
      if (i < plan.length - 1) {
        await expect(title(page)).not.toHaveText(current, { timeout: 15_000 })
        await page.waitForLoadState('networkidle')
        perNext.push(reads.length)
      }
      page.off('request', onRequest)
    }
    await expect(page.getByTestId('triage-done')).toBeVisible({ timeout: 15_000 })
    // Moving on: the next finding, plus a window now and then.
    for (const n of perNext) expect(n).toBeLessThanOrEqual(2)

    // Read back what the session did.
    for (const [findingTitle, action] of Object.entries(decided)) {
      const found = await apiGet<ListBody>(
        page,
        `/api/v1/findings?q=${encodeURIComponent(findingTitle)}&per_page=5`
      )
      const f = found.body.data.find((x) => x.title === findingTitle)!
      expect(f, findingTitle).toBeTruthy()
      if (action === 'c' || action === 'a-then-c') expect(f.status, findingTitle).toBe('confirmed')
      if (action === 's' || action === 'o') expect(f.status, findingTitle).toBe('new')
      if (action === 'f') {
        const approvals = await apiGet<
          Array<{ requested_status: string }> | { data: Array<{ requested_status: string }> }
        >(page, `/api/v1/findings/${f.id}/approvals`)
        const rows = Array.isArray(approvals.body) ? approvals.body : (approvals.body?.data ?? [])
        expect(
          rows.map((r) => r.requested_status),
          findingTitle
        ).toContain('false_positive')
        // The undone request is canceled, not deleted.
        if (undone.has(findingTitle)) {
          expect(
            rows.map((r) => (r as { status?: string }).status),
            findingTitle
          ).toContain('canceled')
        }
      }
    }

    // Exit goes back to the list the session started from.
    await page.getByRole('button', { name: 'Back to the list' }).click()
    await expect(page).toHaveURL(/\/findings\?severity=high$/)
  }
)

test('keys do nothing while a dialog is open', { tag: ['@findings'] }, async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto(`/findings/triage?${QUEUE}`)
  const empty = page.getByTestId('triage-done')
  const finding = title(page)
  await expect(finding.or(empty)).toBeVisible({ timeout: 30_000 })
  test.skip(await empty.isVisible(), 'no triage finding left to open the dialog on')
  const before = await finding.textContent()
  await key(page, '?')
  const dialog = page.getByRole('dialog', { name: 'Triage keys' })
  await expect(dialog).toBeVisible()
  await page.keyboard.press('c')
  await page.keyboard.press('s')
  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()
  await expect(finding).toHaveText(before ?? '')
})
