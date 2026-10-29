import { test, expect } from '../fixtures/authenticated-page'

/**
 * What a hard load of a finding page asks the API for.
 *
 * Regressions this guards:
 *   1. The asset's SLA policy was read from ".../sla-policy/", which the web
 *      server answers with a redirect to ".../sla-policy": two requests for
 *      one read on every finding (and asset) page.
 *   2. The Tenable.sc rescan panel read the integrations list for every
 *      finding, although only a Tenable.sc finding can be rescanned.
 *   3. No request is sent twice.
 *   4. The page reads its finding and panels through one view
 *      (GET /findings/{id}/view, RFC-136): no per-panel read reaches the API.
 */

type ListedFinding = { id: string; tool_name?: string; source?: string }

test.describe('Finding detail requests', { tag: ['@findings'] }, () => {
  test('one read per resource, and no connector list for other tools', async ({ page }) => {
    const listed = page.waitForResponse((r) => /\/api\/v1\/findings\?/.test(r.url()) && r.ok(), {
      timeout: 60_000,
    })
    await page.goto('/findings')
    const body = (await (await listed).json()) as { data?: ListedFinding[] }
    const finding = (body.data ?? []).find((f) => !/tenable/i.test(f.tool_name ?? ''))
    test.skip(!finding, 'the seed has no finding from a tool other than Tenable.sc')

    const seen: string[] = []
    page.on('request', (r) => {
      const u = new URL(r.url())
      if (u.pathname.startsWith('/api/v1/')) seen.push(`${r.method()} ${u.pathname}${u.search}`)
    })
    const id = encodeURIComponent(finding!.id)
    const view = page.waitForResponse(
      (r) => new URL(r.url()).pathname === `/api/v1/findings/${id}/view`,
      { timeout: 60_000 }
    )
    await page.goto(`/findings/${id}`)
    expect((await view).ok()).toBe(true)
    // The finding renders from the view; wait until the page is quiet.
    await expect(page.getByTestId('finding-load-failed')).toHaveCount(0)
    await page.waitForLoadState('networkidle', { timeout: 30_000 }).catch(() => {})
    // One view read, and the finding and its panels never read on their own.
    expect(seen.filter((s) => s === `GET /api/v1/findings/${id}/view`)).toHaveLength(1)
    const panelReads = seen.filter(
      (s) => s.startsWith(`GET /api/v1/findings/${id}`) && !s.endsWith('/view')
    )
    expect(panelReads).toEqual([])
    expect(seen.filter((s) => s.includes('/sla-policy/'))).toEqual([])
    expect(seen.filter((s) => s.includes('/api/v1/integrations'))).toEqual([])
    const counts = new Map<string, number>()
    for (const s of seen) counts.set(s, (counts.get(s) ?? 0) + 1)
    expect([...counts].filter(([, n]) => n > 1).map(([s]) => s)).toEqual([])
  })
})
