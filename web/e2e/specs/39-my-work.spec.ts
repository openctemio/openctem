import path from 'path'
import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * My Work (research 229 §8.5): each persona tab's count is the total of the
 * list it opens (the same quick view or approval queue the API counts), the
 * review queue decides in place or offers a next step, a request of mine can
 * be withdrawn from Requested by me, the page fits a phone with no sideways
 * scroll and has no serious or critical accessibility violation in light and
 * dark. Its request budget is checked with every page by 16-request-budget.
 */

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')

interface AxeResult {
  violations: Array<{ id: string; impact: string | null; nodes: Array<{ target: string[] }> }>
}

async function seriousViolations(page: Page) {
  await page.addScriptTag({ path: AXE })
  const result = (await page.evaluate(async () => {
    const w = window as unknown as {
      axe: { run: (ctx: unknown, opts: unknown) => Promise<AxeResult> }
    }
    return w.axe.run({ include: [['main#content']] }, { resultTypes: ['violations'] })
  })) as AxeResult
  return result.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
}

async function apiGet<T>(page: Page, url: string): Promise<T> {
  return page.evaluate(async (u) => {
    const res = await fetch(u, { credentials: 'same-origin' })
    return res.json()
  }, url)
}

interface QuickViews {
  views: Array<{ key: string; count: number; params: string }>
}

/** The number on a tab ("Assigned to me 7" -> 7), once the counts have loaded. */
async function tabCount(page: Page, name: RegExp): Promise<number> {
  const tab = page.getByRole('tab', { name })
  await expect(tab).toHaveText(/\d+\s*$/)
  const m = ((await tab.textContent()) ?? '').match(/(\d+)\s*$/)
  return m ? Number(m[1]) : 0
}

test('every tab count is the total of the list it opens', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/my-work')
  await expect(page.getByRole('heading', { name: 'My work' })).toBeVisible()
  await expect(page.getByRole('tab', { name: /Assigned to me\s*\d+/ })).toBeVisible()

  const qv = await apiGet<QuickViews>(page, '/api/v1/findings/quick-views')
  const view = (key: string) => qv.views.find((v) => v.key === key)!
  for (const [tab, key] of [
    [/Assigned to me/, 'my_queue'],
    [/My team/, 'my_team'],
    [/Acceptances expiring/, 'my_accepted_expiring'],
  ] as const) {
    const count = await tabCount(page, tab)
    expect(count, `${key} tab count`).toBe(view(key).count)
    const list = await apiGet<{ total: number }>(
      page,
      `/api/v1/findings?${view(key).params}&per_page=1`
    )
    expect(list.total, `${key} list total`).toBe(count)
  }

  const queue = await apiGet<{ queue_counts: { review: number; requested: number } }>(
    page,
    '/api/v1/approvals?queue=requested&status=pending&per_page=1'
  )
  expect(await tabCount(page, /Requested by me/)).toBe(queue.queue_counts.requested)
  const review = page.getByRole('tab', { name: /Awaiting my review/ })
  await tabCount(page, /Requested by me/)
  if (await review.count()) {
    expect(await tabCount(page, /Awaiting my review/)).toBe(queue.queue_counts.review)
  }

  // The rows of Assigned to me open the same list on Findings.
  const viewAll = page.getByRole('link', { name: /View all/ })
  if (await viewAll.count()) {
    await expect(viewAll).toHaveAttribute('href', /related_to=me/)
  }
})

test('the review queue decides in place or offers the next step', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/my-work?tab=review')
  // The tabs follow the permissions, which load with the session.
  await tabCount(page, /Assigned to me/)
  const tab = page.getByRole('tab', { name: /Awaiting my review/ })
  test.skip((await tab.count()) === 0, 'the signed-in person cannot approve')
  await expect(tab).toHaveAttribute('aria-selected', 'true')
  if ((await tabCount(page, /Awaiting my review/)) === 0) {
    await expect(page.getByText('Nothing waits on you')).toBeVisible()
    await expect(
      page
        .getByRole('button', { name: /^Next:/ })
        .or(page.getByRole('link', { name: 'Open all findings' }))
    ).toBeVisible()
  } else {
    const row = page.locator('[data-slot="approval-row"]').first()
    await expect(row.getByRole('button', { name: /Approve/ })).toBeVisible()
    await expect(row.getByRole('button', { name: 'Reject' })).toBeVisible()
    await expect(page.getByText(/Four-eyes/)).toBeVisible()
    // Reject asks for a reason first; cancelling leaves the request pending.
    await row.getByRole('button', { name: 'Reject' }).click()
    const dialog = page.getByRole('dialog')
    await expect(dialog.getByRole('button', { name: 'Reject' })).toBeDisabled()
    await dialog.getByRole('button', { name: 'Cancel' }).click()
    await expect(dialog).toBeHidden()
  }
})

test('a request of mine waits in Requested by me and can be withdrawn', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/my-work')
  // A finding with no pending request: ask for a false positive on it.
  const free = await page.evaluate(async () => {
    const res = await fetch(
      '/api/v1/findings?status=new,confirmed&pending_approval=false&per_page=1',
      {
        credentials: 'same-origin',
      }
    )
    const body = await res.json()
    return body.data?.[0]?.id as string | undefined
  })
  test.skip(!free, 'no open finding without a pending request')
  const note = `E2E My Work: withdrawn by the spec (${Date.now()}).`
  const created = await page.evaluate(
    async ({ id, note }) => {
      const csrf = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/)?.[1] ?? ''
      const res = await fetch(`/api/v1/findings/${id}/approvals/`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': decodeURIComponent(csrf) },
        body: JSON.stringify({
          requested_status: 'false_positive',
          closure_reason: 'detection_error',
          justification: note,
        }),
      })
      return res.status
    },
    { id: free!, note }
  )
  test.skip(created !== 201, `the request was not created (${created})`)

  await page.goto('/my-work?tab=requested')
  const before = await tabCount(page, /Requested by me/)
  expect(before).toBeGreaterThan(0)
  const row = page.locator('[data-slot="approval-row"]').filter({ hasText: note })
  await expect(row).toBeVisible()
  await row.getByRole('button', { name: 'Withdraw' }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: 'Withdraw' }).click()
  await expect(row).toHaveCount(0)
  await expect.poll(() => tabCount(page, /Requested by me/)).toBe(before - 1)
})

for (const scheme of ['light', 'dark'] as const) {
  test(`fits a phone and has no serious accessibility violation in ${scheme}`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme })
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto('/my-work')
    await expect(page.getByRole('tab', { name: /Assigned to me\s*\d+/ })).toBeVisible()
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth
    )
    expect(overflow, 'no sideways page scroll at 390px').toBeLessThanOrEqual(0)
    expect(await seriousViolations(page)).toEqual([])

    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/my-work?tab=requested')
    await expect(page.getByRole('tab', { name: /Requested by me/ })).toHaveAttribute(
      'aria-selected',
      'true'
    )
    expect(await seriousViolations(page)).toEqual([])
  })
}
