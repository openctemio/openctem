import { test, expect } from '@playwright/test'
import { findBreaks } from '../helpers/text-breaks'

/**
 * The layout-break detector (helpers/text-breaks.ts) must catch a labelled
 * button or link that a frame cuts: "Manage" shown as "Mana" at the right edge
 * of a table whose last column was 48 px wide (owner report 2026-11-20). It
 * also must stay quiet for a label that fits and a label that ends in an
 * ellipsis by design.
 *
 * A scroller is no excuse (owner report 2026-11-20, /assets Activity at
 * 390 px: the period token "Last 7 d..." faded at the strip's edge and the
 * tokens after it out of view read as hidden buttons): a control cut by a
 * scroller's edge as the page opens is flagged, and a one-line strip that
 * scrolls sideways may hide no control. A wide table may keep whole columns
 * past its edge (a table is read by scrolling), and a phone title row may not
 * hold one icon control alone at its end.
 */

const page = (frame: string, cell: string) => `<!doctype html><html><body>
<main style="width:600px;padding:8px;font:14px sans-serif">
  <div style="${frame}">
    <table style="width:100%;table-layout:fixed;border-collapse:collapse"><tbody><tr>
      <td style="width:520px">GitHub example-org</td>
      <td style="${cell}">${'<a href="/x" style="white-space:nowrap;display:inline-flex">Manage</a>'}</td>
    </tr></tbody></table>
  </div>
</main></body></html>`

const CLIP = 'overflow-x:clip;width:600px'

test.describe('layout-break detector: controls cut by their frame', { tag: ['@shell'] }, () => {
  test('flags a labelled link cut at the table frame edge', async ({ page: p }) => {
    await p.setContent(page(CLIP, 'width:30px;overflow:hidden'))
    const found = await findBreaks(p)
    expect(found.clipped.join('\n')).toMatch(/control cut by its frame.*Manage/)
  })

  test('flags a labelled link pushed past a clipping table frame', async ({ page: p }) => {
    await p.setContent(page(CLIP, 'width:48px;padding-left:40px'))
    const found = await findBreaks(p)
    expect(found.clipped.join('\n')).toMatch(/control cut by its frame.*Manage/)
  })

  test('is quiet when the label fits', async ({ page: p }) => {
    await p.setContent(page(CLIP, 'width:80px'))
    expect((await findBreaks(p)).clipped).toEqual([])
  })

  test("flags a control cut by a scroller's edge", async ({ page: p }) => {
    await p.setContent(page('overflow-x:auto;width:540px', 'width:80px'))
    expect((await findBreaks(p)).clipped.join('\n')).toMatch(/cut by a scroller's edge.*Manage/)
  })

  test("is quiet for a table column wholly past a scroller's edge", async ({ page: p }) => {
    await p.setContent(page('overflow-x:auto;width:500px', 'width:80px;padding-left:40px'))
    expect((await findBreaks(p)).clipped).toEqual([])
  })
})

const strip = (n: number) => `<!doctype html><html><body>
<main style="width:390px;font:14px sans-serif">
  <div style="display:flex;gap:8px;overflow-x:auto;width:300px;height:36px">
    ${Array.from({ length: n }, (_, i) => `<button style="flex:none;width:120px">Token ${i}</button>`).join('')}
  </div>
</main></body></html>`

test.describe('layout-break detector: sideways strips', { tag: ['@shell'] }, () => {
  test('flags a strip that cuts one token and hides the next', async ({ page: p }) => {
    await p.setContent(strip(4))
    const found = (await findBreaks(p)).clipped.join('\n')
    expect(found).toMatch(/control cut at the edge of a sideways strip: "Token 2"/)
    expect(found).toMatch(/control hidden in a sideways strip: "Token 3"/)
  })

  test('is quiet for a strip whose tokens all fit', async ({ page: p }) => {
    await p.setContent(strip(2))
    expect((await findBreaks(p)).clipped).toEqual([])
  })
})

test.describe('layout-break detector: phone title row', { tag: ['@phone', '@shell'] }, () => {
  const row = (end: string) => `<!doctype html><html><body><main style="width:358px">
  <div data-slot="list-title-row" style="display:flex;justify-content:space-between;width:358px">
    <h2 style="margin:0">Appeared 126</h2>${end}
  </div></main></body></html>`

  test('flags one icon control alone at its end', async ({ page: p }) => {
    await p.setViewportSize({ width: 390, height: 844 })
    await p.setContent(row('<button aria-label="Refresh" style="width:36px;height:36px"></button>'))
    expect((await findBreaks(p)).lopsided.join('\n')).toMatch(/one icon control alone: "Refresh"/)
  })

  test('is quiet for a labelled main action', async ({ page: p }) => {
    await p.setViewportSize({ width: 390, height: 844 })
    await p.setContent(row('<button style="height:36px">Add asset</button>'))
    expect((await findBreaks(p)).lopsided).toEqual([])
  })
})
