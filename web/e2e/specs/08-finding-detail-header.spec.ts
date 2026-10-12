import { test, expect } from '../fixtures/authenticated-page'

/**
 * Finding detail page header and the findings list's title buttons.
 *
 * Regressions this guards:
 *   1. The header labelled every non-target asset "Repository:", so a finding
 *      on a domain or IP read as a code finding. The asset now sits in the
 *      properties rail with its real type.
 *   2. "Activity (0)" in the header while the feed showed an entry (the
 *      synthetic "Recorded by ..." item was not counted). Activity is now the
 *      shared ActivityPanel, opened from the rail's "Activity" summary.
 *   3. Every title button in the findings list was announced as "View finding
 *      details"; its accessible name now carries the finding's title.
 */

type ListedFinding = {
  id: string
  title?: string
  message?: string
  source: string
  asset?: { type?: string }
}

const TARGET_SOURCES = new Set(['pentest', 'bug_bounty', 'red_team', 'manual'])

async function listFindings(page: import('@playwright/test').Page): Promise<ListedFinding[]> {
  const res = page.waitForResponse((r) => /\/api\/v1\/findings\?/.test(r.url()) && r.ok(), {
    timeout: 60_000,
  })
  await page.goto('/findings')
  const body = (await (await res).json()) as { data?: ListedFinding[] }
  return body.data ?? []
}

test.describe('Finding detail header', () => {
  test('names the primary asset by its type', async ({ page }) => {
    const findings = await listFindings(page)
    const f = findings.find(
      (x) => !TARGET_SOURCES.has(x.source) && x.asset?.type && x.asset.type !== 'repository'
    )
    test.skip(!f, 'Needs a scanner finding on a non-repository asset (e.g. a domain)')

    await page.goto(`/findings/${f!.id}`)
    await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible({ timeout: 30_000 })
    // The properties rail names the asset's type under its name
    // ("Domain · Critical asset · Public"), never "Repository" for a domain.
    const rail = page.getByRole('complementary', { name: 'Finding properties' })
    await expect(rail.getByText('Asset', { exact: true })).toBeAttached()
    await expect(rail.getByText(/^Repository\b/)).toHaveCount(0)
    if (f!.asset!.type === 'domain') {
      await expect(rail.getByText(/^Domain\b/)).toBeAttached()
    }
  })

  test('the Activity summary opens the panel, by click and by old ?tab=activity links', async ({
    page,
  }) => {
    const findings = await listFindings(page)
    test.skip(findings.length === 0, 'Needs a finding')

    await page.goto(`/findings/${findings[0].id}`)
    // Activity is not a tab any more.
    await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible({ timeout: 30_000 })
    await expect(page.getByRole('tab', { name: /^Activity/ })).toHaveCount(0)

    const trigger = page.getByRole('button', { name: /^Activity, / })
    await trigger.click()
    const panel = page.getByRole('dialog', { name: /Activity/ })
    await expect(panel).toBeVisible()
    await expect(page).toHaveURL(/[?&]activity=open/)
    await panel.getByRole('radio', { name: 'All' }).click()
    const feed = panel.getByRole('list', { name: 'Activity' })
    await expect(feed).toBeVisible({ timeout: 30_000 })
    expect(await feed.getByRole('listitem').count()).toBeGreaterThan(0)

    // Esc closes it and focus returns to the summary.
    await page.keyboard.press('Escape')
    await expect(panel).toBeHidden()
    await expect(trigger).toBeFocused()

    // An old link to the Activity tab opens the panel.
    await page.goto(`/findings/${findings[0].id}?tab=activity`)
    await expect(page.getByRole('dialog', { name: /Activity/ })).toBeVisible({ timeout: 30_000 })
    await expect(page).toHaveURL(/[?&]activity=open/)
    await expect(page).not.toHaveURL(/tab=activity/)
  })
})

test.describe('Findings list', () => {
  test("each title button's accessible name includes the finding title", async ({ page }) => {
    const findings = await listFindings(page)
    test.skip(findings.length === 0, 'Needs a finding')

    await expect(
      page.getByRole('button', { name: 'View finding details', exact: true })
    ).toHaveCount(0)
    const first = findings[0]
    const title = (first.title || first.message || '').trim()
    test.skip(!title, 'First finding has no title')
    await expect(
      page.getByRole('button', { name: `${title}, view details`, exact: true }).first()
    ).toBeVisible()
  })
})
