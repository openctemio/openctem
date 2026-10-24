import type { Locator, Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Scan list layout at 390px (phone cards) and 1440px (table).
 *
 * Regression guarded: on a phone each scan was a two-column label/value grid
 * and the intensity chip ("Intrusive (full)") overflowed its column onto the
 * next column's text ("about 3 hours ago"). Now:
 *   1. no two text boxes inside a scan card (or a table row) intersect;
 *   2. no text box sticks out of its card (or its table cell);
 *   3. the card puts the name and the last run's state on the first line;
 *   4. a blocked last run says why, with a link to fix it, without hovering.
 */

type Box = { x: number; y: number; width: number; height: number; text: string; owner: number }

/**
 * The line boxes of every visible text node under `root`, tagged with the
 * index of the text node they belong to (two lines of one wrapped text are
 * not an overlap).
 */
async function textBoxes(root: Locator): Promise<Box[]> {
  return root.evaluate((el) => {
    const out: Box[] = []
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT)
    let i = 0
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = (n.textContent ?? '').trim()
      const parent = n.parentElement
      if (!text || !parent) continue
      const style = getComputedStyle(parent)
      if (style.visibility === 'hidden' || style.display === 'none') continue
      // Visually hidden helpers (sr-only) are 1px boxes clipped away.
      if (parent.closest('.sr-only')) continue
      const range = document.createRange()
      range.selectNodeContents(n)
      for (const r of Array.from(range.getClientRects())) {
        if (r.width < 1 || r.height < 1) continue
        out.push({ x: r.x, y: r.y, width: r.width, height: r.height, text, owner: i })
      }
      i += 1
    }
    return out
  }) as Promise<Box[]>
}

function intersects(a: Box, b: Box, tol = 1): boolean {
  return (
    a.x + tol < b.x + b.width &&
    b.x + tol < a.x + a.width &&
    a.y + tol < b.y + b.height &&
    b.y + tol < a.y + a.height
  )
}

function overlaps(boxes: Box[]): string[] {
  const found: string[] = []
  for (let i = 0; i < boxes.length; i++) {
    for (let j = i + 1; j < boxes.length; j++) {
      if (boxes[i].owner === boxes[j].owner) continue
      if (intersects(boxes[i], boxes[j]))
        found.push(`"${boxes[i].text}" overlaps "${boxes[j].text}"`)
    }
  }
  return found
}

async function outside(container: Locator, boxes: Box[]): Promise<string[]> {
  const c = await container.boundingBox()
  if (!c) return []
  return boxes
    .filter((b) => b.x < c.x - 1 || b.x + b.width > c.x + c.width + 1)
    .map((b) => `"${b.text}" sticks out of its container`)
}

async function openScans(page: Page): Promise<boolean> {
  const res = page.waitForResponse((r) => /\/api\/v1\/scans\?/.test(r.url()) && r.ok(), {
    timeout: 60_000,
  })
  await page.goto('/scans')
  const body = (await (await res).json()) as { data?: unknown[] }
  return (body.data?.length ?? 0) > 0
}

test('scan cards at 390px: no overlapping text, name and state on one line', async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 })
  test.skip(!(await openScans(page)), 'Needs at least one scan')

  const cards = page.locator('[data-slot="scan-card"]')
  await expect(cards.first()).toBeVisible({ timeout: 45_000 })
  const n = await cards.count()
  for (let i = 0; i < n; i++) {
    const card = cards.nth(i)
    await card.scrollIntoViewIfNeeded()
    const boxes = await textBoxes(card)
    expect(overlaps(boxes), `card ${i}`).toEqual([])
    expect(await outside(card, boxes), `card ${i}`).toEqual([])

    // The name and the state chip start on the same line.
    const title = await card.locator('[data-slot="scan-card-title"]').boundingBox()
    const status = card.locator('[data-slot="scan-card-status"]')
    if ((await status.count()) > 0 && title) {
      const s = await status.boundingBox()
      expect(s && Math.abs(s.y - title.y), `card ${i} state on the title line`).toBeLessThan(12)
    }
  }

  // A blocked last run explains itself on the card.
  const blocked = cards.filter({ has: page.locator('[data-state="blocked"]') })
  if ((await blocked.count()) > 0) {
    await expect(blocked.first().locator('[data-slot="blocked-run-hint"]')).toBeVisible()
  }

  await testInfo.attach('scans-390.png', {
    body: await page.screenshot({ fullPage: true }),
    contentType: 'image/png',
  })
})

test('scan table at 1440px: no overlapping text, nothing outside its cell', async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  test.skip(!(await openScans(page)), 'Needs at least one scan')

  const rows = page.locator('table tbody tr')
  await expect(rows.first()).toBeVisible({ timeout: 45_000 })
  const n = await rows.count()
  for (let i = 0; i < n; i++) {
    const row = rows.nth(i)
    expect(overlaps(await textBoxes(row)), `row ${i}`).toEqual([])
    const cells = row.locator('td')
    const m = await cells.count()
    for (let j = 0; j < m; j++) {
      const cell = cells.nth(j)
      expect(await outside(cell, await textBoxes(cell)), `row ${i} cell ${j}`).toEqual([])
    }
  }

  await testInfo.attach('scans-1440.png', {
    body: await page.screenshot({ fullPage: true }),
    contentType: 'image/png',
  })
})
