import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * /sensors on a phone (owner report 2026-10-31, iPhone, one degraded sensor):
 *   1. the fleet health strip: no tile's text runs into the next tile, no two
 *      tiles overlap, and the labels and values of a row share one line (a
 *      toggle tile's label sat lower: a <button> centres its content);
 *   2. the tab strip: no tab cut at the edge without the fade that says more
 *      are hidden;
 *   3. the list toolbar: the search placeholder is not cut short;
 *   4. the state legend is one line until opened, and opened it stays inside
 *      the page;
 *   5. the figures agree: a sensor that stopped claiming (storage full) is
 *      counted in Needs attention with its reason, is not counted as able to
 *      take jobs, and its card says why it is degraded;
 *   6. no sideways page scroll.
 * The organization's sensor list is answered with that one sensor (the shape
 * the API returned for it), so the spec does not depend on a running sensor.
 * The same checks run at 1440px, where the strip is one row.
 */

function degradedSensor() {
  const now = Date.now()
  const iso = (ms: number) => new Date(now - ms).toISOString()
  return {
    id: '00000000-0000-4000-8000-0000000000a1',
    tenant_id: '00000000-0000-4000-8000-000000000001',
    name: 'e2e-full-sensor',
    type: 'worker',
    capabilities: ['scan'],
    execution_mode: 'daemon',
    status: 'active',
    health: 'online',
    api_key_prefix: 'oc_s_e2',
    version: 'v0.29.1',
    hostname: 'e2e-host',
    ip_address: '203.0.113.213',
    cpu_percent: 3,
    memory_percent: 21,
    max_concurrent_jobs: 5,
    current_jobs: 0,
    labels: {},
    config: {},
    metadata: {},
    last_seen_at: iso(14_000),
    started_at: iso(3_600_000),
    total_findings: 0,
    total_scans: 0,
    error_count: 0,
    created_at: iso(86_400_000),
    updated_at: iso(14_000),
    effective: { tools: ['nuclei'], capabilities: ['scan'], max_concurrent_jobs: 5 },
    outbox: {
      pending_count: 0,
      pending_bytes: 0,
      oldest_age_seconds: 0,
      dead_letter_count: 0,
      evicted_count: 0,
      reported_at: iso(14_000),
    },
    state: 'degraded',
    health_reasons: [
      {
        code: 'stopped_claiming',
        severity: 'critical',
        message:
          'The sensor stopped claiming new jobs because its local storage is full, so its scans wait.',
      },
    ],
    local_store: {
      level: 'high',
      stop_claiming: true,
      reason: '9 % of the volume free, below 15 %',
      total_bytes: 0,
      quota_bytes: 8_589_934_592,
      disk_level: 'ok',
      sweeps: 11,
      reported_at: iso(14_000),
    },
    content_refresh_supported: true,
    config_health: 'ok',
    heartbeat_interval_seconds: 33,
    heartbeat_due_at: new Date(now + 19_000).toISOString(),
  }
}

async function openSensors(page: Page) {
  await page.route(
    (url) => url.pathname === '/api/v1/sensors',
    async (route) => {
      if (route.request().method() !== 'GET') return route.continue()
      const items = [degradedSensor()]
      await route.fulfill({ json: { items, total: items.length, page: 1, per_page: 200 } })
    }
  )
  await page.goto('/sensors')
  await expect(page.locator('main [data-slot="metric-strip"]')).toBeVisible({ timeout: 45_000 })
  await expect(page.getByText('e2e-full-sensor').first()).toBeVisible()
}

async function layoutDefects(page: Page) {
  return page.evaluate(() => {
    const out: string[] = []
    const doc = document.documentElement
    if (doc.scrollWidth > doc.clientWidth) {
      out.push(`page scrolls sideways by ${doc.scrollWidth - doc.clientWidth}px`)
    }
    const strip = document.querySelector('main [data-slot="metric-strip"]')!
    const tiles = Array.from(
      strip.querySelectorAll<HTMLElement>(':scope > [data-slot="metric-tile"]')
    )
    const box = (e: Element) => e.getBoundingClientRect()
    tiles.forEach((tile, i) => {
      const tb = box(tile)
      const name = tile.querySelector('[data-slot="metric-label"]')?.textContent ?? `tile ${i}`
      for (const e of Array.from(tile.querySelectorAll('*'))) {
        const b = box(e)
        if (b.width > 0 && (b.right > tb.right + 0.5 || b.left < tb.left - 0.5)) {
          out.push(`"${(e.textContent ?? '').trim().slice(0, 30)}" runs out of "${name}"`)
          break
        }
      }
      for (const other of tiles.slice(i + 1)) {
        const ob = box(other)
        const w = Math.min(tb.right, ob.right) - Math.max(tb.left, ob.left)
        const h = Math.min(tb.bottom, ob.bottom) - Math.max(tb.top, ob.top)
        if (w > 1.5 && h > 1.5) out.push(`tile "${name}" overlaps the next one`)
      }
    })
    // Tiles of one row: same label top, same value top.
    const rows = new Map<number, HTMLElement[]>()
    for (const t of tiles) {
      const top = Math.round(box(t).top)
      rows.set(top, [...(rows.get(top) ?? []), t])
    }
    for (const row of rows.values()) {
      for (const slot of ['metric-label', 'metric-value']) {
        const tops = row.map((t) => Math.round(box(t.querySelector(`[data-slot="${slot}"]`)!).top))
        if (Math.max(...tops) - Math.min(...tops) > 1)
          out.push(`${slot} tops differ in a row: ${tops}`)
      }
    }
    // Tabs: a tab past the strip's edge needs the end fade.
    const strip2 = document.querySelector<HTMLElement>('main [data-slot="tabs-list"]')!
    const sb = box(strip2)
    for (const tab of Array.from(strip2.children)) {
      const b = box(tab)
      if (b.right > sb.right + 0.5 && strip2.dataset.fadeEnd !== 'true') {
        out.push(`tab "${(tab.textContent ?? '').trim()}" is cut with no fade`)
      }
    }
    // The search placeholder fits its box.
    const input = document.querySelector<HTMLInputElement>('main [data-slot="list-search-input"]')
    if (input) {
      const value = input.value
      input.value = input.placeholder
      if (input.scrollWidth > input.clientWidth + 1)
        out.push(
          `search placeholder cut: "${input.placeholder}" ${input.scrollWidth}>${input.clientWidth} ${getComputedStyle(input).fontSize}`
        )
      input.value = value
    }
    return out
  })
}

for (const width of [390, 1440] as const) {
  test(
    `sensors page at ${width}px: strip, tabs, toolbar and legend fit, figures agree @phone`,
    { tag: ['@sensors'] },
    async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: width === 390 ? 844 : 900 })
      await openSensors(page)
      const strip = page.locator('main [data-slot="metric-strip"]')
      await testInfo.attach(`strip-${width}`, {
        body: await strip.screenshot(),
        contentType: 'image/png',
      })
      expect(await layoutDefects(page)).toEqual([])

      // The figures agree with the sensor: degraded because it stopped claiming.
      const tile = (label: string) =>
        strip.locator('[data-slot="metric-tile"]').filter({
          has: page.locator('[data-slot="metric-label"]', { hasText: label }),
        })
      await expect(tile('Fleet health').locator('[data-slot="metric-value"]')).toContainText(
        /^0(?!\d)/
      )
      await expect(tile('Needs attention').locator('[data-slot="metric-value"]')).toHaveText('1')
      await expect(tile('Needs attention')).toContainText('storage full')
      await expect(tile('Needs attention')).not.toContainText('nothing to fix')
      if (width === 390) {
        // The reason is in the DOM twice (the phone card and the table row,
        // one hidden by CSS); the visible one must show it.
        await expect(
          page.getByText('takes no new jobs: storage full').locator('visible=true').first()
        ).toBeVisible()
      }

      // The legend is one line until it is opened.
      const legend = page.locator('main [data-slot="sensor-state-legend"]')
      await legend.scrollIntoViewIfNeeded()
      expect((await legend.boundingBox())!.height).toBeLessThanOrEqual(40)
      await legend.locator('summary').click()
      await expect(
        legend.getByText('Each sensor is judged against its own heartbeat interval.')
      ).toBeVisible()
      const opened = await legend.evaluate((el) => ({
        overflow: el.scrollWidth - el.clientWidth,
        right: el.getBoundingClientRect().right,
        page: document.documentElement.clientWidth,
      }))
      expect(opened.overflow).toBeLessThanOrEqual(0)
      expect(opened.right).toBeLessThanOrEqual(opened.page)

      // The drawer says what is wrong and what to do.
      await page.getByText('e2e-full-sensor').first().click()
      const drawer = page.getByRole('dialog')
      await expect(drawer.getByText('Not taking new jobs: storage full')).toBeVisible()
      await expect(drawer.getByText(/Free disk space on the sensor host/)).toBeVisible()
    }
  )
}
