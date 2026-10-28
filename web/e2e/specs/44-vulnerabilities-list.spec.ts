import path from 'path'
import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * The vulnerabilities list /vulnerabilities (api/docs/architecture/vulnerability-page.md, "The list").
 *
 * - One row per CVE: the seeded CVE is listed, and its findings count equals
 *   the findings list filtered by that CVE (scope parity).
 * - The metric strip's tiles are filters that reach the URL and the request.
 * - A row opens the vulnerability page; the sidebar has the entry.
 * - No horizontal page scroll at 1440 px and 390 px, no serious axe
 *   violation in light or dark.
 * - Bulk actions: a selected row's findings export as CSV and retest
 *   through the bulk bar; a saved view opens through ?view=<id>.
 *
 * The CI seed (e2e/ci/seed.sh) gives two findings E2E_CVE (default
 * CVE-2099-0101); without it the tests skip.
 */

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')
const CVE = process.env.E2E_CVE ?? 'CVE-2099-0101'

interface ListRow {
  cve_id: string
  findings: number
}

async function seriousViolations(page: Page) {
  await page.addScriptTag({ path: AXE })
  const result = (await page.evaluate(async () => {
    const w = window as unknown as {
      axe: {
        run: (
          ctx: unknown,
          opts: unknown
        ) => Promise<{
          violations: Array<{
            id: string
            impact: string | null
            nodes: Array<{ target: string[] }>
          }>
        }>
      }
    }
    return w.axe.run({ include: [['main#content']] }, { resultTypes: ['violations'] })
  })) as {
    violations: Array<{ id: string; impact: string | null; nodes: Array<{ target: string[] }> }>
  }
  return result.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
}

/** Opens the list and returns the seeded CVE's row, or null when the seed has none. */
async function openList(page: Page, query = ''): Promise<ListRow | null> {
  const answer = page.waitForResponse(
    (r) => r.url().includes('/api/v1/vulnerability-exposures?') && r.request().method() === 'GET',
    { timeout: 45_000 }
  )
  await page.goto(`/vulnerabilities${query}`)
  const res = await answer
  if (!res.ok()) return null
  const body = (await res.json()) as { data: ListRow[] }
  await page.waitForLoadState('networkidle')
  return body.data.find((r) => r.cve_id === CVE) ?? null
}

async function noHorizontalScroll(page: Page) {
  return page.evaluate(
    () => document.documentElement.scrollWidth <= document.documentElement.clientWidth
  )
}

for (const scheme of ['light', 'dark'] as const) {
  test(`vulnerabilities list at 1440px in ${scheme}: rows, strip, no scroll, axe`, async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.emulateMedia({ colorScheme: scheme })
    const row = await openList(page, '?state=all')
    test.skip(!row, `no seeded finding of ${CVE}`)

    await expect(page.getByRole('heading', { level: 1, name: 'Vulnerabilities' })).toBeVisible()
    await expect(
      page.getByRole('link', { name: `Vulnerability page for ${CVE}` }).first()
    ).toBeVisible()
    await expect(page.getByText(/Counts are in your data scope/)).toBeVisible()
    // The main navigation has the entry.
    await expect(page.locator('a[href="/vulnerabilities"]').first()).toBeVisible()
    expect(await noHorizontalScroll(page)).toBe(true)
    expect(await seriousViolations(page)).toEqual([])
    await page.screenshot({
      path: testInfo.outputPath(`vulnerabilities-1440-${scheme}.png`),
      fullPage: true,
    })
  })
}

test('a row counts what the findings list filtered by its CVE shows', async ({ page }) => {
  const row = await openList(page, '?state=all')
  test.skip(!row, `no seeded finding of ${CVE}`)
  const total = await page.evaluate(async (cve) => {
    const res = await fetch(`/api/v1/findings?cve_id=${cve}&state=all&per_page=1`, {
      credentials: 'same-origin',
    })
    return ((await res.json()) as { total: number }).total
  }, CVE)
  expect(row!.findings).toBe(total)
})

test('a strip tile filters the list through the URL', async ({ page }) => {
  const row = await openList(page)
  test.skip(!row, `no seeded finding of ${CVE}`)
  const next = page.waitForResponse(
    (r) => r.url().includes('/api/v1/vulnerability-exposures?') && r.url().includes('kev=true')
  )
  await page
    .getByRole('button', { name: /Known exploited/ })
    .first()
    .click()
  await next
  await expect(page).toHaveURL(/kev=true/)
  await expect(page.getByRole('button', { name: 'Remove filter Known exploited' })).toBeVisible()
})

test('a row opens the vulnerability page, and Back keeps the filters', async ({ page }) => {
  const row = await openList(page, '?state=all&sort=cve')
  test.skip(!row, `no seeded finding of ${CVE}`)
  await page
    .getByRole('link', { name: `Vulnerability page for ${CVE}` })
    .first()
    .click()
  await expect(page).toHaveURL(new RegExp(`/vulnerabilities/${CVE}$`))
  await page.goBack()
  await expect(page).toHaveURL(/state=all/)
  await expect(page).toHaveURL(/sort=cve/)
})

test('phone width: a card per row, no horizontal scroll @phone', async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const row = await openList(page, '?state=all')
  test.skip(!row, `no seeded finding of ${CVE}`)
  await expect(page.locator('[data-slot="vuln-card"]').first()).toBeVisible()
  expect(await noHorizontalScroll(page)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('vulnerabilities-390.png'), fullPage: true })
})

test('a selected row exports its findings and retests through the bulk bar', async ({ page }) => {
  const row = await openList(page, '?state=all')
  test.skip(!row, `no seeded finding of ${CVE}`)
  await page
    .getByRole('checkbox', { name: `Select ${CVE}` })
    .first()
    .check()
  const bar = page.getByRole('toolbar', { name: /selected rows/i })
  await expect(bar).toBeVisible()

  const download = page.waitForEvent('download')
  await bar.getByRole('button', { name: 'Export' }).click()
  const file = await download
  const csv = await file.createReadStream().then(
    (stream) =>
      new Promise<string>((resolve) => {
        let out = ''
        stream.on('data', (c) => (out += String(c)))
        stream.on('end', () => resolve(out))
      })
  )
  expect(csv.split('\n')[0]).toContain('asset_name')
  expect(csv).toContain(CVE)

  const retest = page.waitForResponse(
    (r) =>
      r.url().includes('/api/v1/vulnerability-exposures/retests') && r.request().method() === 'POST'
  )
  await bar.getByRole('button', { name: 'Retest' }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: 'Retest' }).click()
  expect((await retest).status()).toBe(202)
})

test('a saved view opens through ?view=<id> and runs as the viewer', async ({ page }) => {
  const row = await openList(page, '?state=all')
  test.skip(!row, `no seeded finding of ${CVE}`)
  const id = await page.evaluate(async () => {
    const res = await fetch('/api/v1/views', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        page: 'vulnerabilities',
        name: `e2e ${Date.now()}`,
        query: 'state=all&sort=cve',
      }),
    })
    return ((await res.json()) as { id: string }).id
  })
  try {
    const list = page.waitForResponse(
      (r) => r.url().includes('/api/v1/vulnerability-exposures?') && r.url().includes(`view=${id}`)
    )
    await page.goto(`/vulnerabilities?view=${id}`)
    expect((await list).status()).toBe(200)
    await expect(
      page.getByRole('link', { name: `Vulnerability page for ${CVE}` }).first()
    ).toBeVisible()
  } finally {
    await page.evaluate(async (viewId) => {
      await fetch(`/api/v1/views/${viewId}`, { method: 'DELETE', credentials: 'same-origin' })
    }, id)
  }
})
