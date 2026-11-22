import { test, expect } from '@playwright/test'
import { findBreaks } from '../helpers/text-breaks'

/**
 * The layout-break detector (helpers/text-breaks.ts) must catch a select value
 * cut with no ellipsis: scope "One-off entries" in Vietnamese at 390 px showed
 * its value cut mid-word, and the sweep passed, because the value box carried
 * `line-clamp-1` (a computed line clamp) while being a flex box, where neither
 * a line clamp nor an ellipsis is drawn. It also must stay quiet for the kit's
 * fixed value box (the text in its own truncated box) and for a block box that
 * ends in an ellipsis.
 */

const LONG = 'Các mục một lần được duyệt trong phạm vi quét của tổ chức'

const field = (value: string) => `<!doctype html><html><body>
<main style="width:360px;padding:8px;font:14px sans-serif">
  <button type="button" role="combobox" aria-label="Entries"
    style="display:flex;align-items:center;justify-content:space-between;gap:8px;width:180px;height:36px;padding:0 12px;white-space:nowrap">
    ${value}
    <svg width="16" height="16" style="flex-shrink:0"></svg>
  </button>
</main></body></html>`

const CLAMPED_FLEX = `<span style="display:flex;align-items:center;gap:8px;overflow:hidden;-webkit-box-orient:vertical;-webkit-line-clamp:1">${LONG}</span>`
const ELLIPSIS_FLEX = `<span style="display:flex;min-width:0;overflow:hidden;text-overflow:ellipsis">${LONG}</span>`
const KIT = `<span style="display:flex;align-items:center;gap:8px;min-width:0;overflow:hidden"><span style="min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${LONG}</span></span>`
const CONTENTS = `<span style="display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="display:contents">${LONG}</span></span>`
const CHIP = `<span style="display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="display:inline-flex;align-items:center">${LONG}</span></span>`
const BLOCK = `<span style="display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${LONG}</span>`

test.describe(
  'layout-break detector: select values cut with no ellipsis',
  { tag: ['@shell'] },
  () => {
    test('flags a flex value box with a line clamp (no clamp is drawn)', async ({ page }) => {
      await page.setContent(field(CLAMPED_FLEX))
      const found = await findBreaks(page)
      expect(found.clipped.join('\n')).toMatch(/cut, no ellipsis: "Các mục/)
    })

    test('flags a flex value box with text-overflow (no ellipsis is drawn)', async ({ page }) => {
      await page.setContent(field(ELLIPSIS_FLEX))
      const found = await findBreaks(page)
      expect(found.clipped.join('\n')).toMatch(/cut, no ellipsis: "Các mục/)
    })

    test('is quiet for the kit value: text in its own truncated box', async ({ page }) => {
      await page.setContent(field(KIT))
      expect((await findBreaks(page)).clipped).toEqual([])
    })

    test('is quiet for a block box that ends in an ellipsis', async ({ page }) => {
      await page.setContent(field(BLOCK))
      expect((await findBreaks(page)).clipped).toEqual([])
    })

    // A `display: contents` span (a phone card's value wrapper) flows inline
    // inside the ellipsis box: the mark is drawn.
    test('is quiet for text in a display: contents wrapper under an ellipsis', async ({ page }) => {
      await page.setContent(field(CONTENTS))
      expect((await findBreaks(page)).clipped).toEqual([])
    })

    test('flags a chip (inline-flex) cut inside an ellipsis box', async ({ page }) => {
      await page.setContent(field(CHIP))
      expect((await findBreaks(page)).clipped.join('\n')).toMatch(/cut, no ellipsis: "Các mục/)
    })
  }
)
