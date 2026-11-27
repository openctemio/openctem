import { test, expect, type Page } from '@playwright/test'
import { findMatrixBreaks } from '../helpers/layout-matrix'
import { probeRowMix } from '../helpers/page-anatomy'

/**
 * Self-test of the layout matrix's control-shape detectors
 * (helpers/layout-matrix.ts), from the owner reports of 2026-11-27:
 *   - deadSpace: a filter token "Target: All" in a box sized for its longest
 *     value, its chevron mid-way with empty room after it;
 *   - floatingAction: the "Validate" action of a 1500 px "Waiting for you" row
 *     standing in the middle of the row;
 *   - tallControl: a channel select whose value wrapped onto three lines beside
 *     32 px buttons;
 *   - pastEdge: a toolbar's "Refresh" and "Display" cut at the window's edge;
 *   - sizeMismatch (probeRowMix with fonts): a repository's Findings toolbar
 *     whose filter triggers were taller, or set in another size, than the
 *     search beside them ("các button cái to cái nhỏ").
 * Each flags its defect and stays quiet for the right layout.
 */

const doc = (body: string) =>
  `<!doctype html><html><body style="margin:0;font:14px sans-serif">${body}</body></html>`

async function at(p: Page, width: number, body: string) {
  await p.setViewportSize({ width, height: 900 })
  await p.setContent(doc(body))
  return findMatrixBreaks(p)
}

const chevron = '<svg width="16" height="16" style="flex:none"></svg>'
const token = (style: string, inner: string) =>
  `<main style="width:900px"><div style="display:flex;gap:8px">
    <button role="combobox" style="display:inline-flex;align-items:center;gap:6px;padding:0 8px 0 12px;height:32px;border:1px solid #ccc;${style}">${inner}</button>
    <button style="height:32px">Refresh</button>
  </div></main>`

test.describe('layout matrix detector: dead space in a control', { tag: ['@shell'] }, () => {
  test('flags a chevron far from the control end', async ({ page }) => {
    const found = await at(
      page,
      1440,
      token('width:240px;justify-content:flex-start', `<span>Target: All</span>${chevron}`)
    )
    expect(found.deadSpace.join('\n')).toMatch(/trailing icon \d+px from the end of "Target: All"/)
  })

  test('flags empty room between the text and a chevron pinned to the end', async ({ page }) => {
    const found = await at(
      page,
      1440,
      token('width:240px;justify-content:space-between', `<span>Target: All</span>${chevron}`)
    )
    expect(found.deadSpace.join('\n')).toMatch(/px of empty room before the trailing icon/)
  })

  test('is quiet for a token that hugs its content', async ({ page }) => {
    const found = await at(page, 1440, token('', `<span>Target: All</span>${chevron}`))
    expect(found.deadSpace).toEqual([])
  })

  test('is quiet for a held width and for a field filling its column', async ({ page }) => {
    const held = await at(
      page,
      1440,
      `<main style="width:900px"><div style="display:flex" data-hold-width="true">
        <button style="display:flex;justify-content:space-between;width:240px;padding:0 8px">
          <span>Practice: All</span>${chevron}</button></div></main>`
    )
    expect(held.deadSpace).toEqual([])
    const field = await at(
      page,
      1440,
      `<main style="width:900px"><form style="width:400px"><label>Channel</label>
        <button role="combobox" style="display:flex;justify-content:space-between;width:100%;padding:0 8px">
          <span>Ops</span>${chevron}</button></form></main>`
    )
    expect(field.deadSpace).toEqual([])
  })
})

const queueRow = (cols: string) => `<main style="width:1500px"><ul style="padding:0;margin:0">
  <li style="display:grid;grid-template-columns:${cols};align-items:center;gap:12px;padding:12px 16px">
    <span>1</span>
    <span><b>Fixes waiting for validation</b><br>Marked fixed; no re-check has confirmed it yet.</span>
    <a data-slot="button" href="/x" style="justify-self:end;padding:4px 10px;border:1px solid">Validate</a>
  </li></ul></main>`

test.describe('layout matrix detector: floating row action', { tag: ['@shell'] }, () => {
  test('flags an action that stops mid-row', async ({ page }) => {
    const found = await at(page, 1920, queueRow('56px minmax(0,32rem) auto; justify-content:start'))
    expect(found.floatingAction.join('\n')).toMatch(/action "Validate" floats \d+px short/)
  })

  test("is quiet for an action at the row's end", async ({ page }) => {
    const found = await at(page, 1920, queueRow('56px minmax(0,1fr) auto'))
    expect(found.floatingAction).toEqual([])
  })
})

const toolbar = (valueStyle: string) => `<main style="width:900px">
  <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-start">
    <button data-slot="select-trigger" style="width:160px;min-height:32px;display:flex;align-items:center;justify-content:space-between;padding:0 8px">
      <span style="${valueStyle}">Product security channel for the platform</span>${chevron}</button>
    <button data-slot="button" style="height:32px">Refresh</button>
    <button data-slot="button" style="height:32px">Display</button>
  </div></main>`

test.describe('layout matrix detector: control taller than its row', { tag: ['@shell'] }, () => {
  test('flags a select whose value wraps onto several lines', async ({ page }) => {
    const found = await at(page, 1440, toolbar('min-width:0;overflow-wrap:anywhere'))
    expect(found.tallControl.join('\n')).toMatch(/is \d+px tall beside 32px controls/)
  })

  test('is quiet for a one-line value with an ellipsis', async ({ page }) => {
    const found = await at(
      page,
      1440,
      toolbar('min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis')
    )
    expect(found.tallControl).toEqual([])
  })
})

const shell = (row: string) => `<div style="display:flex;width:100vw;overflow:clip">
  <aside style="width:240px;flex:none">Nav</aside>
  <main id="content" style="flex:1;min-width:0;overflow-y:auto;height:100vh">${row}</main></div>`

test.describe('layout matrix detector: control past the edge', { tag: ['@shell'] }, () => {
  test('flags toolbar buttons cut by the window edge', async ({ page }) => {
    const found = await at(
      page,
      1024,
      shell(`<div style="display:flex;gap:8px;width:900px">
        <button style="width:720px;flex:none">Channel</button>
        <button style="flex:none">Refresh</button><button style="flex:none">Display</button></div>`)
    )
    expect(found.pastEdge.join('\n')).toMatch(
      /control "Display" \d+px past the (window|page column)/
    )
  })

  test('is quiet for a toolbar that wraps', async ({ page }) => {
    const found = await at(
      page,
      1024,
      shell(`<div style="display:flex;flex-wrap:wrap;gap:8px">
        <button style="width:600px">Channel</button><button>Refresh</button><button>Display</button></div>`)
    )
    expect(found.pastEdge).toEqual([])
  })

  test('is quiet for a table column out of view in its scroller', async ({ page }) => {
    const found = await at(
      page,
      1024,
      shell(`<div data-slot="table-container" style="overflow:auto;width:500px"><table><tr>
        <td style="min-width:900px">Name</td><td><button>Open</button></td></tr></table></div>`)
    )
    expect(found.pastEdge).toEqual([])
  })
})

const row = (a: string, b: string) => `<main style="width:900px">
  <div data-slot="list-toolbar" style="display:flex;gap:8px;align-items:center">
    <input placeholder="Search" style="height:32px;font-size:14px;box-sizing:border-box">
    <button data-slot="button" style="${a}">All severities</button>
    <button data-slot="button" style="${b}">All statuses</button>
  </div></main>`

test.describe('layout matrix detector: sizes in one row', { tag: ['@shell'] }, () => {
  const size = (p: Parameters<typeof probeRowMix>[0]) => probeRowMix(p, { fonts: true })
  const doc32 = 'height:32px;font-size:14px'

  test('flags a control taller than its neighbours', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.setContent(doc(row(doc32, 'height:44px;font-size:14px')))
    expect((await size(page)).length).toBe(1)
  })

  test('flags buttons of one height in different text sizes', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.setContent(doc(row(doc32, 'height:32px;font-size:12px')))
    const mixed = await size(page)
    expect(mixed.length).toBe(1)
    expect(mixed[0].controls.map((c) => c.font)).toContain(12)
  })

  test('is quiet for one height and one text size', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.setContent(doc(row(doc32, doc32)))
    expect(await size(page)).toEqual([])
  })

  test('compares a field apart from buttons (16 px field text on a phone)', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.setContent(
      doc(`<main style="width:380px"><div data-slot="list-toolbar" style="display:flex;gap:8px">
        <input style="height:36px;font-size:16px;box-sizing:border-box;width:160px">
        <button data-slot="button" style="height:36px;font-size:13px">Filters</button>
        <button data-slot="button" style="height:36px;font-size:13px">Display</button></div></main>`)
    )
    expect(await size(page)).toEqual([])
  })
})

const ruled = (
  chipStyle: string
) => `<main style="width:900px"><table style="border-collapse:collapse">
  <tbody><tr style="border-bottom:1px solid #ccc;height:36px">
    <td style="padding:0 8px;height:36px;overflow:visible">
      <div style="height:20px;display:flex;flex-wrap:wrap;gap:4px">
        <span data-slot="badge" style="display:inline-block;height:20px;${chipStyle}">KEV</span>
        <span data-slot="badge" style="display:inline-block;height:20px;${chipStyle}">Ransomware</span>
      </div></td></tr>
  <tr style="height:36px"><td>Next</td></tr></tbody></table></main>`

test.describe('layout matrix detector: content crowding its row edge', { tag: ['@shell'] }, () => {
  test('flags a chip that wraps across the row bottom border', async ({ page }) => {
    // 80 px wide: the second chip wraps below the first, past the row.
    const found = await at(
      page,
      1440,
      ruled('width:70px').replace('display:flex;', 'display:flex;width:80px;')
    )
    expect(found.cellCrowd.join('\n')).toMatch(
      /chip "Ransomware" [\d.]+px past its row's bottom edge/
    )
  })

  test('is quiet for chips on one line, centred in the row', async ({ page }) => {
    const found = await at(page, 1440, ruled('width:70px'))
    expect(found.cellCrowd).toEqual([])
  })
})
