import { test, expect, type Page } from '@playwright/test'
import { findMatrixBreaks } from '../helpers/layout-matrix'

/**
 * Self-test of the layout matrix's underPinned detector (helpers/layout-matrix.ts):
 * a notice that stays while the page scrolls, or text under a sticky or fixed
 * layer. Owner report v0.25.0, wide desktop: the "vulnerability data not
 * loaded" banner sat above the scrolling page and the page's content slid out
 * right under it ("7 pages" half hidden).
 * It must stay quiet for a sticky table header over its rows, a notice that
 * scrolls away with the page, a bar whose room the page keeps (nothing under
 * it at rest or at the end) and a sticky toolbar over text the page has
 * scrolled past.
 */

const doc = (body: string) =>
  `<!doctype html><html><body style="margin:0;font:14px sans-serif">${body}</body></html>`

async function at(p: Page, body: string) {
  await p.setViewportSize({ width: 1440, height: 900 })
  await p.setContent(doc(body))
  return (await findMatrixBreaks(p)).underPinned
}

const paras = (n: number) =>
  Array.from(
    { length: n },
    (_, i) => `<p style="margin:0;padding:8px 0">Row ${i + 1} of the list</p>`
  ).join('')

const BANNER = 'Vulnerability data not loaded'

/** The shell: a header, the banner slot and the scrolling main below them. */
const shell = (banners: string, main: string) => `
  <div style="display:flex;flex-direction:column;height:100vh">
    <header style="height:48px;flex:none">OpenCTEM</header>
    <div data-slot="shell-banners">${banners}</div>
    <main id="content" style="flex:1;min-height:0;overflow-y:auto;padding:16px">${main}</main>
  </div>`

const notice = `<div role="alert" style="padding:12px;background:#fee">${BANNER}</div>`

test.describe('layout matrix detector: under pinned', { tag: ['@shell'] }, () => {
  test('flags a sticky notice over the text of a scrolled page', async ({ page }) => {
    const found = await at(
      page,
      `<main style="padding:16px">
        <div role="alert" style="position:sticky;top:0;padding:12px;background:#fee">${BANNER}</div>
        <h1 style="margin:0">7 pages</h1>${paras(120)}</main>`
    )
    const all = found.join('\n')
    expect(all).toMatch(/^"Row \d+ of the list" under .*div\[role=alert\] \(sticky, scrolled\)/m)
    expect(all).toMatch(/notice "Vulnerability data not loaded" stays while the page scrolls/)
  })

  test('flags a banner above the scrolling main', async ({ page }) => {
    const found = await at(page, shell(notice, `<h1 style="margin:0">7 pages</h1>${paras(120)}`))
    expect(found).toHaveLength(1)
    expect(found[0]).toMatch(
      /^notice "Vulnerability data not loaded" stays while the page scrolls at .*shell-banners/
    )
  })

  test('flags a fixed bar over the top of the page that keeps no room for it', async ({ page }) => {
    const found = await at(
      page,
      `<div style="position:fixed;top:0;left:0;right:0;height:56px;background:#fff">Toolbar</div>
      <main><h1 style="margin:0;padding:8px">7 pages</h1>${paras(120)}</main>`
    )
    expect(found.join('\n')).toMatch(/"7 pages" under div \(fixed, at the top\)/)
  })

  test('flags a fixed bar over the end of the page that keeps no room for it', async ({ page }) => {
    const found = await at(
      page,
      `<main>${paras(120)}<p style="margin:0">Last line</p></main>
      <div style="position:fixed;bottom:0;left:0;right:0;height:56px;background:#fff">Save</div>`
    )
    expect(found.join('\n')).toMatch(
      /^"(Row \d+ of the list|Last line)" under div \(fixed, at the end\)/
    )
  })

  test('is quiet for a sticky table header over its rows', async ({ page }) => {
    const rows = Array.from(
      { length: 120 },
      (_, i) => `<tr><td>Finding ${i + 1}</td><td>High</td></tr>`
    ).join('')
    const table = `<table style="width:100%;border-collapse:collapse">
      <thead style="position:sticky;top:0;background:#fff"><tr><th>Name</th><th>Severity</th></tr></thead>
      <tbody>${rows}</tbody></table>`
    expect(await at(page, `<main style="padding:16px">${table}</main>`)).toEqual([])
    expect(await at(page, shell('', table))).toEqual([])
  })

  test('is quiet for a notice in the scroller that scrolls away', async ({ page }) => {
    expect(await at(page, shell('', `${notice}<h1>7 pages</h1>${paras(120)}`))).toEqual([])
  })

  test('is quiet for a banner above a page that does not scroll', async ({ page }) => {
    expect(await at(page, shell(notice, `<h1>7 pages</h1>${paras(3)}`))).toEqual([])
  })

  test('is quiet for fixed bars whose room the page keeps', async ({ page }) => {
    const found = await at(
      page,
      `<div style="position:fixed;top:0;left:0;right:0;height:56px;background:#fff">Toolbar</div>
      <main style="padding:56px 0">${paras(120)}</main>
      <div style="position:fixed;bottom:0;left:0;right:0;height:56px;background:#fff">Save</div>`
    )
    expect(found).toEqual([])
  })

  test('is quiet for a sticky toolbar over text the page scrolled past', async ({ page }) => {
    const found = await at(
      page,
      shell(
        '',
        `<div style="position:sticky;top:0;height:48px;background:#fff">Filters</div>${paras(120)}`
      )
    )
    expect(found).toEqual([])
  })

  test('puts the page back where it was', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.setContent(doc(shell(notice, paras(120))))
    await page.evaluate(() => document.querySelector('#content')!.scrollTo({ top: 120 }))
    await findMatrixBreaks(page)
    expect(await page.evaluate(() => document.querySelector('#content')!.scrollTop)).toBe(120)
  })
})
