import { test, expect, type Page } from '@playwright/test'
import { findMatrixBreaks } from '../helpers/layout-matrix'

/**
 * Self-test of the layout matrix's hollowCard detector (helpers/layout-matrix.ts):
 * a framed card whose last content ends more than max(64 px, 30% of its
 * height) above its inner bottom edge. Owner report 2026-11-26: the
 * dashboard's CTEM loop card stood 120 px of empty card under its tiles,
 * and the matrix said nothing.
 * It must stay quiet for a card sized to its content, for a card stretched
 * by a neighbour that fills the row (equal-height rows are by design), and
 * for the fill areas: a chart's plot box and an empty state that centres
 * itself in the room it is given.
 */

const doc = (body: string) =>
  `<!doctype html><html><body style="margin:0;font:14px sans-serif">${body}</body></html>`

async function at(p: Page, body: string, width = 1440) {
  await p.setViewportSize({ width, height: 900 })
  await p.setContent(doc(`<main style="padding:16px">${body}</main>`))
  return (await findMatrixBreaks(p)).hollowCard
}

const CARD = 'border:1px solid #ddd;border-radius:8px;background:#fff;padding:16px'
const card = (inner: string, style = '') =>
  `<section data-slot="card" style="${CARD};${style}">${inner}</section>`
const tiles = (h: number) =>
  `<h3 style="margin:0">The CTEM loop</h3><div style="height:${h}px;background:#eef">tiles</div>`

test.describe('layout matrix detector: hollow card', { tag: ['@shell'] }, () => {
  test('flags a card that stands well above its content', async ({ page }) => {
    // 272 px stored height for about 150 px of tiles (the #4408 report).
    const found = await at(page, card(tiles(110), 'height:272px;box-sizing:border-box'))
    expect(found.join('\n')).toMatch(/card ends \d+px below its last content \(272px tall/)
  })

  test('is quiet for a card sized to its content', async ({ page }) => {
    expect(await at(page, card(tiles(110)))).toEqual([])
  })

  test('is quiet below the limit (a short gap in a short card)', async ({ page }) => {
    // 150 px card, content ends about 40 px above its padding: under 64 px.
    expect(await at(page, card(tiles(50), 'height:150px;box-sizing:border-box'))).toEqual([])
  })

  test('measures text by its line, not by the box that holds it', async ({ page }) => {
    const found = await at(
      page,
      card(
        '<p style="margin:0;height:240px">One short line</p>',
        'height:280px;box-sizing:border-box'
      )
    )
    expect(found.join('\n')).toMatch(/card ends/)
  })

  test('is quiet for a card stretched by a neighbour that fills the row', async ({ page }) => {
    const row = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      ${card(tiles(40))}${card(tiles(300))}</div>`
    expect(await at(page, row)).toEqual([])
  })

  test('flags every card of a row whose floor is taller than all of them', async ({ page }) => {
    const row = `<div style="display:grid;grid-template-columns:1fr 1fr;grid-auto-rows:minmax(300px,auto);gap:16px">
      ${card(tiles(40))}${card(tiles(60))}</div>`
    const found = await at(page, row)
    expect(found.join('\n')).toMatch(/\(2 cards\)/)
  })

  test('climbs from a card to its grid cell past a heading above it', async ({ page }) => {
    const cell = (h: number) =>
      `<div style="display:flex;flex-direction:column"><h2 style="margin:0">Heading</h2>${card(tiles(h), 'flex:1')}</div>`
    const row = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">${cell(40)}${cell(300)}</div>`
    expect(await at(page, row)).toEqual([])
  })

  test("is quiet for a chart's fixed plot box", async ({ page }) => {
    const plot = `<h3 style="margin:0">Trend</h3>
      <div class="recharts-responsive-container" style="height:220px"><svg width="400" height="80"></svg></div>`
    expect(await at(page, card(plot))).toEqual([])
  })

  test('is quiet for an empty state that fills the card and centres itself', async ({ page }) => {
    const empty = `<div data-slot="empty-state" style="flex:1;display:flex;align-items:center;justify-content:center"><p>No certificates yet</p></div>`
    expect(
      await at(
        page,
        card(empty, 'height:300px;box-sizing:border-box;display:flex;flex-direction:column')
      )
    ).toEqual([])
  })

  test('flags a short empty state left at the top of a tall card', async ({ page }) => {
    const empty = `<div data-slot="empty-state"><p style="margin:0">No certificates yet</p></div>`
    expect((await at(page, card(empty, 'height:300px;box-sizing:border-box'))).join('\n')).toMatch(
      /card ends/
    )
  })

  test('is not fooled by a frameless box or a text area', async ({ page }) => {
    const body = `<div style="height:300px;background:#fafafa"><p>Plain section</p></div>
      <textarea style="${CARD};height:300px;width:400px"></textarea>`
    expect(await at(page, body)).toEqual([])
  })
})
