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
 */

type ListedFinding = { id: string; tool_name?: string; source?: string }

test.describe('Finding detail requests', () => {
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
    const read = page.waitForResponse(
      (r) => new URL(r.url()).pathname === `/api/v1/findings/${id}`,
      {
        timeout: 60_000,
      }
    )
    await page.goto(`/findings/${id}`)
    await read
    // The panels fetch after the finding renders; wait until the page is quiet.
    await page.waitForLoadState('networkidle', { timeout: 30_000 }).catch(() => {})
    await expect.poll(() => seen.length, { timeout: 30_000 }).toBeGreaterThan(5)
    await page.waitForLoadState('networkidle', { timeout: 30_000 }).catch(() => {})
    expect(seen.filter((s) => s.includes('/sla-policy/'))).toEqual([])
    expect(seen.filter((s) => s.includes('/api/v1/integrations'))).toEqual([])
    const counts = new Map<string, number>()
    for (const s of seen) counts.set(s, (counts.get(s) ?? 0) + 1)
    expect([...counts].filter(([, n]) => n > 1).map(([s]) => s)).toEqual([])
  })
})
