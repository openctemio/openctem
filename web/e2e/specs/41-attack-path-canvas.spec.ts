import path from 'path'
import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Attack paths (research/229 mockups/attack-path.html): the flow canvas from
 * the internet through an entry point and two hops to a crown jewel at
 * 1440px (nodes named for screen readers, edges drawn, the arrow keys follow
 * the edges, hover lights the routes through a node), the list view at 390px
 * with no horizontal scroll, and no serious accessibility violation in light
 * and dark. The spec creates its own assets and relationships through the API
 * and deletes them after, so it does not depend on (or change) the seed.
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

async function api(page: Page, method: 'POST' | 'PATCH' | 'DELETE', url: string, data?: unknown) {
  const res = await page.evaluate(
    async ({ method, url, data }) => {
      const r = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: data === undefined ? undefined : JSON.stringify(data),
      })
      return { status: r.status, body: await r.text() }
    },
    { method, url, data }
  )
  return res
}

interface Graph {
  entry: string
  hopA: string
  hopB: string
  jewel: string
  names: Record<'entry' | 'hopA' | 'hopB' | 'jewel', string>
}

/** entry (public) → hopA → jewel, entry → hopB → jewel. Null when the API refuses (module off). */
async function createGraph(page: Page): Promise<Graph | null> {
  const run = Math.random().toString(36).slice(2, 8)
  const names = {
    entry: `ap-e2e-entry-${run}`,
    hopA: `ap-e2e-hop-a-${run}`,
    hopB: `ap-e2e-hop-b-${run}`,
    jewel: `ap-e2e-jewel-${run}`,
  }
  const ids: Record<string, string> = {}
  const specs: Array<[keyof typeof names, string, string]> = [
    ['entry', 'service', 'public'],
    ['hopA', 'service', 'private'],
    ['hopB', 'service', 'private'],
    ['jewel', 'database', 'private'],
  ]
  for (const [k, type, exposure] of specs) {
    const r = await api(page, 'POST', '/api/v1/assets', {
      name: names[k],
      type,
      exposure,
      criticality: k === 'jewel' ? 'critical' : 'medium',
    })
    if (r.status >= 300) return null
    ids[k] = JSON.parse(r.body).id
  }
  await api(page, 'PATCH', `/api/v1/assets/${ids.jewel}/crown-jewel`, {
    is_crown_jewel: true,
    business_impact_score: 90,
    business_impact_notes: 'e2e',
  })
  for (const [from, to] of [
    ['entry', 'hopA'],
    ['entry', 'hopB'],
    ['hopA', 'jewel'],
    ['hopB', 'jewel'],
  ]) {
    const r = await api(page, 'POST', `/api/v1/assets/${ids[from]}/relationships/`, {
      type: 'has_access_to',
      source_asset_id: ids[from],
      target_asset_id: ids[to],
    })
    if (r.status >= 300) return null
  }
  return { entry: ids.entry, hopA: ids.hopA, hopB: ids.hopB, jewel: ids.jewel, names }
}

async function deleteGraph(page: Page, g: Graph | null) {
  if (!g) return
  for (const id of [g.jewel, g.hopA, g.hopB, g.entry])
    await api(page, 'DELETE', `/api/v1/assets/${id}`)
}

test.describe('attack path view', () => {
  for (const scheme of ['light', 'dark'] as const) {
    test(`canvas at 1440px in ${scheme}: nodes, edges, keys, hover, axe`, async ({
      page,
    }, testInfo) => {
      await page.setViewportSize({ width: 1440, height: 900 })
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
      await page.goto('/assets')
      const g = await createGraph(page)
      test.skip(!g, 'assets or relationships could not be created (module off or no permission)')
      try {
        await page.goto(`/attack-paths?target=${g!.jewel}&paths=all`)
        await expect(
          page.getByRole('heading', { level: 1, name: `Path to ${g!.names.jewel}` })
        ).toBeVisible({
          timeout: 30_000,
        })
        const canvas = page.getByTestId('attack-path-canvas')
        await expect(canvas.getByTestId('flow-node')).toHaveCount(4)
        // Internet edge plus four relationships.
        await expect(canvas.locator('.react-flow__edge')).toHaveCount(5)

        const entry = page.getByRole('button', {
          name: new RegExp(`^Entry point .*${g!.names.entry}`),
        })
        const hopA = page.getByRole('button', { name: new RegExp(`^Hop .*${g!.names.hopA}`) })
        const hopB = page.getByRole('button', { name: new RegExp(`^Hop .*${g!.names.hopB}`) })
        const jewel = page.getByRole('button', {
          name: new RegExp(`^Crown jewel .*${g!.names.jewel}`),
        })
        await expect(entry).toBeVisible()
        await expect(jewel).toBeVisible()

        // Readable layout: left to right at full size (zoom 1, so no text under
        // 12px), nothing overlaps, the side cards under the canvas.
        const [be, ba, bb, bj] = await Promise.all(
          [entry, hopA, hopB, jewel].map((l) => l.boundingBox())
        )
        expect(be!.x).toBeLessThan(ba!.x)
        expect(ba!.x).toBeLessThan(bj!.x)
        expect(Math.abs(ba!.x - bb!.x)).toBeLessThan(2)
        expect(ba!.y + ba!.height).toBeLessThanOrEqual(bb!.y)
        const zoom = await canvas
          .locator('.react-flow__viewport')
          .evaluate((el) => new DOMMatrix(getComputedStyle(el).transform).a)
        expect(zoom).toBeGreaterThan(0.99)
        const box = await canvas.boundingBox()
        expect(bj!.x + bj!.width).toBeLessThanOrEqual(box!.x + box!.width)
        const aside = await page.getByRole('heading', { name: /^Choke points/ }).boundingBox()
        expect(aside!.y).toBeGreaterThan(box!.y + box!.height)
        expect(
          await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)
        ).toBe(true)

        // Hover lights the routes through a node and dims the others.
        // The canvas fits its view once the nodes are measured; hover again
        // if the first hover landed before that.
        await expect(async () => {
          await page.mouse.move(5, 5)
          await hopB.hover()
          await expect(hopB).toHaveAttribute('data-state', 'lit', { timeout: 1000 })
          await expect(hopA).toHaveAttribute('data-state', 'dim', { timeout: 1000 })
        }).toPass({ timeout: 10_000 })
        await page.mouse.move(5, 5)

        // Keyboard: one tab stop, the arrows follow the edges.
        // The arrow goes to the hop nearest the entry's row: either hop.
        // A re-measure of the canvas can drop focus between the focus call and
        // the key press, so retry the pair until the arrow lands.
        const focused = page.locator('[data-testid=flow-node]:focus')
        await expect(async () => {
          await entry.focus()
          await page.keyboard.press('ArrowRight')
          await expect(focused).toHaveCount(1, { timeout: 1000 })
        }).toPass({ timeout: 10_000 })
        await expect(focused).toHaveAccessibleName(/^Hop /)
        await page.keyboard.press('Escape')

        expect(await seriousViolations(page)).toEqual([])
        await testInfo.attach(`attack-path-1440-${scheme}.png`, {
          body: await page.screenshot({ fullPage: true }),
          contentType: 'image/png',
        })
      } finally {
        await deleteGraph(page, g)
      }
    })
  }

  test('list view at 390px: every step in order, no horizontal scroll, axe @phone', async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto('/assets')
    const g = await createGraph(page)
    test.skip(!g, 'assets or relationships could not be created (module off or no permission)')
    try {
      await page.goto(`/attack-paths?target=${g!.jewel}&paths=all`)
      const list = page.getByTestId('attack-path-list')
      await expect(list).toBeVisible({ timeout: 30_000 })
      await expect(page.getByTestId('attack-path-canvas')).toHaveCount(0)
      await expect(list.getByRole('heading', { name: 'Shortest path' })).toBeVisible()
      await expect(list.getByText(g!.names.jewel).first()).toBeVisible()
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)
      ).toBe(true)
      expect(await seriousViolations(page)).toEqual([])
      await testInfo.attach('attack-path-390.png', {
        body: await page.screenshot({ fullPage: true }),
        contentType: 'image/png',
      })
    } finally {
      await deleteGraph(page, g)
    }
  })

  test('an unknown asset shows an error state, not an empty graph', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/attack-paths?target=00000000-0000-0000-0000-000000000000')
    await expect(page.getByText(/Failed to load attack paths|not found/i).first()).toBeVisible({
      timeout: 30_000,
    })
  })
})
