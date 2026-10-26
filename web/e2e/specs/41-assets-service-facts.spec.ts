import path from 'path'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * The asset list's Service facts cell: one line of WHOLE chips that fits its
 * cell at every width (status code, port, then "+N" before anything is
 * cut), the "+N" popover lists every fact, and the table drops its
 * lower-priority columns instead of scrolling sideways at 1440px with the
 * sidebar open. The seed (web/e2e/ci/seed.sh) adds an HTTP service with more
 * facts than the cell holds.
 */

const AXE = path.resolve(__dirname, '../../node_modules/axe-core/axe.min.js')

interface AxeResult {
  violations: Array<{ id: string; impact: string | null; nodes: Array<{ target: string[] }> }>
}

/** Serious axe violations inside `include` (the page's main region by default). */
async function seriousViolations(
  page: import('@playwright/test').Page,
  include: string[] = ['main#content']
) {
  await page.addScriptTag({ path: AXE })
  const result = (await page.evaluate(async (selectors) => {
    const w = window as unknown as {
      axe: { run: (ctx: unknown, opts: unknown) => Promise<AxeResult> }
    }
    return w.axe.run({ include: selectors.map((s) => [s]) }, { resultTypes: ['violations'] })
  }, include)) as AxeResult
  return result.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
}

async function openAssets(
  page: import('@playwright/test').Page,
  context: import('@playwright/test').BrowserContext,
  baseURL: string | undefined,
  width: number,
  sidebarOpen: boolean
) {
  await context.addCookies([
    { name: 'sidebar_state', value: String(sidebarOpen), url: baseURL ?? 'http://localhost:3000' },
  ])
  await page.setViewportSize({ width, height: 900 })
  await page.goto('/assets')
  const row = page.locator('main tbody tr', { hasText: 'e2e-edge.example.com' })
  const seeded = await row
    .waitFor({ state: 'visible', timeout: 30_000 })
    .then(() => true)
    .catch(() => false)
  await page.waitForLoadState('networkidle')
  return { row, seeded }
}

/** Chips of every facts line that are cut by their line or their cell. */
async function clippedChips(page: import('@playwright/test').Page) {
  return page.locator('[data-testid="surface-facts-line"]').evaluateAll((lines) =>
    lines.flatMap((line) => {
      const box = line.getBoundingClientRect()
      const cell = (line.closest('td') as HTMLElement).getBoundingClientRect()
      return [...line.children]
        .map((c) => ({ text: c.textContent ?? '', b: c.getBoundingClientRect() }))
        .filter(
          ({ b }) =>
            b.left < box.left - 0.5 ||
            b.right > box.right + 0.5 ||
            b.right > cell.right + 0.5 ||
            b.width === 0
        )
        .map(({ text, b }) => `${text} [${Math.round(b.left)}-${Math.round(b.right)}]`)
    })
  )
}

const CASES: Array<{ width: number; sidebarOpen: boolean }> = [
  { width: 1280, sidebarOpen: true },
  { width: 1440, sidebarOpen: true },
  { width: 1440, sidebarOpen: false },
  { width: 1920, sidebarOpen: true },
]

for (const { width, sidebarOpen } of CASES) {
  test(`service facts at ${width}px, sidebar ${sidebarOpen ? 'open' : 'collapsed'}: whole chips, +N, no sideways scroll`, async ({
    page,
    context,
    baseURL,
  }, testInfo) => {
    const { row, seeded } = await openAssets(page, context, baseURL, width, sidebarOpen)
    test.skip(!seeded, 'no seeded HTTP service')

    // No chip runs out of its line or its cell, none is squeezed.
    expect(await clippedChips(page)).toEqual([])

    // Status first as its code, then the port, then "+N" with the rest.
    const line = row.getByTestId('surface-facts-line')
    await expect(line.locator('[data-slot="fact-chip"]').first()).toHaveAttribute(
      'data-status',
      '301'
    )
    await expect(line.getByText('443/https')).toBeVisible()
    const more = line.locator('[data-slot="facts-more"]')
    await expect(more).toBeVisible()

    // The table fits its frame: lower-priority columns hide first, the row
    // keeps name, risk, scope and service facts.
    const overflow = await page
      .locator('main [data-slot="table-container"]')
      .evaluate((el) => el.scrollWidth - el.clientWidth)
    expect(overflow, 'table scrolls sideways').toBeLessThanOrEqual(1)
    for (const name of [/^Name/, /^Risk/, /^Scope/, /^Service facts/]) {
      await expect(page.getByRole('columnheader', { name })).toBeVisible()
    }

    await testInfo.attach(`assets-facts-${width}-${sidebarOpen ? 'open' : 'closed'}.png`, {
      body: await page.screenshot(),
      contentType: 'image/png',
    })
  })
}

test('the +N popover lists every fact; axe finds nothing serious', async ({
  page,
  context,
  baseURL,
}) => {
  const { row, seeded } = await openAssets(page, context, baseURL, 1440, true)
  test.skip(!seeded, 'no seeded HTTP service')
  expect(await seriousViolations(page)).toEqual([])

  await row.locator('[data-slot="facts-more"]').click()
  const popover = page.locator('[data-slot="popover-content"]')
  await expect(popover).toBeVisible()
  await expect(popover.getByText('Moved Permanently')).toBeVisible()
  await expect(popover.getByText('Behind Cloudflare')).toBeVisible()
  await expect(popover.getByText('162.159.140.229')).toBeVisible()
  await expect(popover.getByText('172.66.0.227')).toBeVisible()
  await expect(popover.getByText('nginx', { exact: false })).toBeVisible()
  // Opening the popover does not open the row's drawer.
  await expect(page.locator('[data-slot="sheet-content"]')).toHaveCount(0)
  expect(await seriousViolations(page, ['main#content', '[data-slot="popover-content"]'])).toEqual(
    []
  )
})
