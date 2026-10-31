import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * The exposure flow and the intake panel follow their own card width (api
 * docs/architecture/dashboards.md, "Exposure flow and intake", layout bands):
 * at each card width the columns fill the card (no empty side gutters from 960 px up), never overlap, the ring stays inside its
 * column, the card never scrolls sideways, and a wire starts right after the
 * row it leaves (no long gap between a source and its curve on a wide card).
 */

const WIDTHS = [480, 720, 960, 1200, 1440, 1600, 1920] as const

/** Largest empty gutter (px) between the card's content box and the composition. */
const MAX_GUTTER = 32

const widget = (id: string, metric: string, viz: string) => ({
  widget_type: 'metric',
  x: 0,
  y: 0,
  w: 12,
  h: 6,
  config: {
    v: 2,
    id,
    data: { kind: 'metric', metric, filter: {}, time: {} },
    viz: { type: viz, options: {} },
  },
})

async function api(page: Page, method: 'POST' | 'DELETE', url: string, data?: unknown) {
  return page.evaluate(
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
}

/** Layout facts of one connected visual inside a widget cell. */
async function measure(page: Page, index: number) {
  return page.locator(`[data-widget-index="${index}"]`).evaluate((cell) => {
    type Box = { l: number; r: number; t: number; b: number }
    const box = (e: Element): Box => {
      const r = e.getBoundingClientRect()
      return { l: r.left, r: r.right, t: r.top, b: r.bottom }
    }
    const hit = (a: Box, b: Box) => a.l < b.r - 1 && b.l < a.r - 1 && a.t < b.b - 1 && b.t < a.b - 1
    const frame = cell.querySelector('section')
    const root = cell.querySelector('[data-band]')
    if (!frame || !root) return null
    const kids = [...root.children].filter(
      (c) => c.tagName.toLowerCase() !== 'svg' && getComputedStyle(c).position !== 'absolute'
    )
    const overlaps: string[] = []
    for (let a = 0; a < kids.length; a++)
      for (let b = a + 1; b < kids.length; b++)
        if (hit(box(kids[a]), box(kids[b]))) overlaps.push(`${a}/${b}`)
    const ring = root.querySelector('[data-k="ring"]')
    let ringInside = true
    if (ring?.parentElement) {
      const rb = box(ring)
      const col = box(ring.parentElement)
      ringInside = rb.l >= col.l - 1 && rb.r <= col.r + 1
    }
    const layer = [...root.children].find((c) => c.tagName.toLowerCase() === 'svg')
    const origin = root.getBoundingClientRect()
    const starts = [...(layer?.querySelectorAll('path') ?? [])]
      .filter((p) => !p.classList.contains('animate-flow-dash'))
      .map((p) => /^M([\d.-]+) ([\d.-]+)/.exec(p.getAttribute('d') ?? ''))
      .filter((m): m is RegExpExecArray => !!m)
      .map((m) => [origin.left + Number(m[1]), origin.top + Number(m[2])])
    // From each source row's label block to the wire leaving that row.
    const gaps = [...root.querySelectorAll('[data-wire-out^="s:"]')].flatMap((out) => {
      const row = out.closest('a')
      const label = row?.querySelector('.min-w-0')
      if (!label) return []
      const lb = box(label)
      const s = starts.find(([, y]) => y >= lb.t - 12 && y <= lb.b + 12)
      return s ? [Math.round(s[0] - lb.r)] : []
    })
    // Empty space between the card's content box and the first/last column: a
    // composition that fills its card leaves only the padding.
    const cs = getComputedStyle(frame)
    const fb = box(frame)
    const innerL = fb.l + parseFloat(cs.paddingLeft) + parseFloat(cs.borderLeftWidth)
    const innerR = fb.r - parseFloat(cs.paddingRight) - parseFloat(cs.borderRightWidth)
    const first = kids.length ? box(kids[0]) : null
    const last = kids.length ? box(kids[kids.length - 1]) : null
    return {
      leftGutter: first ? Math.round(first.l - innerL) : 0,
      rightGutter: last ? Math.round(innerR - last.r) : 0,
      band: root.getAttribute('data-band'),
      overflow: frame.scrollWidth - frame.clientWidth,
      overlaps,
      ringInside,
      wires: starts.length,
      gaps,
    }
  })
}

test(
  'exposure flow and intake keep their parts together at every card width',
  { tag: ['@dashboard'] },
  async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 2400 })
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.goto('/')
    const created = await api(page, 'POST', '/api/v1/me/dashboards', {
      name: `e2e-flow-${Math.random().toString(36).slice(2, 8)}`,
      columns: 1,
      layout: [
        widget('w_flow', 'exposure.flow', 'flow'),
        widget('w_in', 'ingest.intake', 'intake'),
      ],
    })
    test.skip(created.status >= 300, 'dashboard could not be created')
    const id = (JSON.parse(created.body) as { id: string }).id
    try {
      await page.evaluate((ref) => {
        try {
          localStorage.setItem('openctem:dashboard-choice', ref)
        } catch {
          /* private mode */
        }
      }, `personal:${id}`)
      await page.reload()
      await expect(page.getByTestId('exposure-flow')).toBeVisible({ timeout: 45_000 })
      for (const w of WIDTHS) {
        await page.addStyleTag({
          content: `[data-widget-index]{width:${w}px !important;max-width:${w}px !important}`,
        })
        await page.waitForTimeout(400)
        for (const index of [0, 1]) {
          const m = await measure(page, index)
          if (!m) continue // the widget has no figures here (not measured)
          const at = `widget ${index} at ${w}px (${m.band})`
          expect(m.overflow, `${at}: sideways scroll`).toBeLessThanOrEqual(0)
          expect(m.overlaps, `${at}: columns overlap`).toEqual([])
          expect(m.ringInside, `${at}: ring outside its column`).toBe(true)
          if (m.band !== 'narrow' && w >= 960) {
            expect(m.leftGutter, `${at}: empty gutter before the sources`).toBeLessThanOrEqual(
              MAX_GUTTER
            )
            expect(m.rightGutter, `${at}: empty gutter after the summary`).toBeLessThanOrEqual(
              MAX_GUTTER
            )
          }
          if (m.band === 'narrow') expect(m.wires, `${at}: wires on one column`).toBe(0)
          for (const g of m.gaps)
            expect(g, `${at}: a wire starts far from its source`).toBeLessThanOrEqual(80)
        }
      }
    } finally {
      await api(page, 'DELETE', `/api/v1/me/dashboards/${id}`)
    }
  }
)
