import { test, expect } from '@playwright/test'
import { findBreaks } from '../helpers/text-breaks'

/**
 * The layout-break detector (helpers/text-breaks.ts) must catch a labelled
 * button or link that a frame cuts: "Manage" shown as "Mana" at the right edge
 * of a table whose last column was 48 px wide (owner report 2026-11-20). It
 * also must stay quiet for a label that fits, a label that ends in an
 * ellipsis by design, and a scroller (its content is reachable).
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

  test('is quiet in a scroller', async ({ page: p }) => {
    await p.setContent(page('overflow-x:auto;width:540px', 'width:80px'))
    expect((await findBreaks(p)).clipped).toEqual([])
  })
})
