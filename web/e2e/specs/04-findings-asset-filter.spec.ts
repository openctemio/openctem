import { test, expect } from '../fixtures/authenticated-page'

/**
 * Critical Flow #4: Findings filtered by asset
 *
 * Verifies the regression we hit before: opening findings with an
 * `?assetId=...` query param must show counts that match the actual
 * filtered list — not the unfiltered totals. Previously the summary
 * cards showed "9 critical" while the filtered table showed "1 critical".
 *
 * The check is:
 *   1. Pick the first asset that has at least one finding (or skip).
 *   2. Open /findings?assetId=<id>
 *   3. Read both the summary card count and the table row count.
 *   4. Assert summary count <= total table rows AND that the URL
 *      filter parameter is honoured.
 */

test.describe('Findings asset-id filter', () => {
  test('findings page renders with no filter', async ({ page }) => {
    await page.goto('/findings')
    await page.waitForLoadState('networkidle')

    // Either a row, an empty state, or a filter chip area must exist.
    const filterArea = page
      .getByRole('table')
      .or(page.getByText(/no findings/i))
      .or(page.getByRole('region', { name: /finding/i }))
    await expect(filterArea.first()).toBeVisible({ timeout: 20_000 })
  })

  test('findings filtered by assetId honour the filter', async ({ page }) => {
    // Step 1: find an asset with findings to filter by. Asset rows open a
    // sheet and carry no /assets/<id> link, so the id comes from the list
    // response the page loads (scraping links picked up "/assets/changes"
    // and skipped this test on every run).
    type Asset = { id: string; finding_count?: number }
    const assetsRes = page.waitForResponse(
      (r) => new URL(r.url()).pathname === '/api/v1/assets' && r.ok(),
      { timeout: 30_000 }
    )
    await page.goto('/assets')
    const assets = ((await (await assetsRes).json()) as { data?: Asset[] }).data ?? []
    const asset = assets.find((a) => (a.finding_count ?? 0) > 0)
    test.skip(!asset, 'No asset with findings — seed findings to enable this test')
    const assetId = asset!.id

    // Step 2: open findings with the asset filter; the list request must
    // carry it to the API.
    const findingsRes = page.waitForResponse(
      (r) => {
        const u = new URL(r.url())
        return u.pathname === '/api/v1/findings' && u.searchParams.get('asset_id') === assetId
      },
      { timeout: 30_000 }
    )
    await page.goto(`/findings?assetId=${assetId}`)
    const res = await findingsRes
    expect(res.ok()).toBeTruthy()
    const findings = ((await res.json()) as { data?: Array<{ asset_id: string }> }).data ?? []

    // Step 3: the URL must still carry the filter. The page rewrites the old
    // `assetId` link parameter to the canonical `asset_id`, so a shared old
    // link keeps its filter.
    await expect(page).toHaveURL(new RegExp(`[?&]asset_id=${assetId}(&|$)`))
    expect(page.url()).not.toContain('assetId=')

    // Step 4: only this asset's findings come back, and the table shows them.
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.every((f) => f.asset_id === assetId)).toBeTruthy()
    await expect(page.getByRole('table').first()).toBeVisible({ timeout: 15_000 })
  })

  // TODO: Regression assertion for "summary count != filtered count" bug.
  // This requires:
  //   - data-testid hooks on the severity summary cards (e.g.
  //     data-testid="finding-summary-critical")
  //   - data-testid="findings-table-row" on each table row
  //   - Then assert: summary["critical"] === count(rows where severity=critical)
  // Add the hooks first, then enable the assertion in this file.
})
