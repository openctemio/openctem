import { test, expect, type Page } from '@playwright/test'
import { findEmptyTail, findMatrixBreaks, openedPath } from '../helpers/layout-matrix'

/**
 * Self-test of the MVP acceptance v2 detectors (helpers/layout-matrix.ts):
 * each must flag the defect it was written for and stay quiet for the layout
 * that is right.
 *   - a control past its rail column (the finding watchers control near 2000 px);
 *   - text cut at a table scroller's edge with no ellipsis (/remediation/campaigns
 *     Due column at 1024 px, sidebar expanded);
 *   - a row of its own holding only "Updated ..." or one small control above the
 *     first data row (/my-work at iPad width);
 *   - two primary buttons for one job;
 *   - a stretched field, text line or far rail on a 1920 px screen.
 */

const doc = (body: string) =>
  `<!doctype html><html><body style="margin:0;font:14px sans-serif">${body}</body></html>`

async function at(p: Page, width: number, body: string) {
  await p.setViewportSize({ width, height: 900 })
  await p.setContent(doc(body))
  return findMatrixBreaks(p)
}

const rail = (control: string) => `<main style="width:900px">
  <div style="display:grid;grid-template-columns:600px 280px;gap:20px">
    <section><p>Panel</p></section>
    <div><div style="display:flex;gap:8px"><span>Watchers</span>${control}</div></div>
  </div></main>`

test.describe('layout matrix detector: control past its column', { tag: ['@shell'] }, () => {
  test('flags a control that runs past its rail column', async ({ page }) => {
    const found = await at(
      page,
      1440,
      rail('<button style="flex:none;width:320px;white-space:nowrap">Manage watchers</button>')
    )
    expect(found.pastPanel.join('\n')).toMatch(/control past its column.*Manage watchers/)
  })

  test('is quiet when the control fits its column', async ({ page }) => {
    const found = await at(page, 1440, rail('<button style="min-width:0">Manage watchers</button>'))
    expect(found.pastPanel).toEqual([])
  })

  test('allows a ghost button pulled to its text by a small start margin', async ({ page }) => {
    const found = await at(page, 1440, rail('<button style="margin-left:-8px">Manage</button>'))
    expect(found.pastPanel).toEqual([])
  })
})

const table = (cell: string) => `<main style="width:700px">
  <div style="overflow-x:auto;width:500px"><table style="border-collapse:collapse"><tbody><tr>
    <td style="width:420px;min-width:420px">Quarterly patch campaign</td>
    <td style="white-space:nowrap">${cell}</td>
  </tr></tbody></table></div></main>`

test.describe('layout matrix detector: text cut at a frame edge', { tag: ['@shell'] }, () => {
  test('flags a cell cut by the table scroller with no ellipsis', async ({ page }) => {
    const found = await at(page, 1024, table('Apr 29, 2026, overdue'))
    expect(found.cutText.join('\n')).toMatch(/text cut at a frame edge.*overdue/)
  })

  test('is quiet for a cell that ends in an ellipsis', async ({ page }) => {
    const found = await at(
      page,
      1024,
      table(
        '<span style="display:block;width:60px;overflow:hidden;text-overflow:ellipsis">Apr 29, 2026, overdue</span>'
      )
    )
    expect(found.cutText).toEqual([])
  })

  test('is quiet for a column wholly past the scroller edge', async ({ page }) => {
    const found = await at(
      page,
      1024,
      table('<span style="padding-left:120px">Apr 29</span>').replace(
        '420px;min-width:420px',
        '480px;min-width:480px'
      )
    )
    expect(found.cutText).toEqual([])
  })
})

/** A page tab strip as the shared one draws it: 240 px wide, tabs past its end. */
const tabStrip = (attrs: string, overflow = 'auto') => `<main style="width:1000px">
  <nav ${attrs} style="width:240px;display:flex;gap:16px;overflow-x:${overflow};white-space:nowrap">
    <a style="flex-shrink:0">Overview</a><a style="flex-shrink:0">Findings</a>
    <a style="flex-shrink:0">Ports and services</a><a style="flex-shrink:0">How we found it</a>
  </nav></main>`

test.describe('layout matrix detector: page tab strip', { tag: ['@shell'] }, () => {
  test('is quiet for a tab past the edge of a scrolling strip that fades it', async ({ page }) => {
    const found = await at(
      page,
      1024,
      tabStrip('data-tab-strip data-fade-start="false" data-fade-end="true"')
    )
    expect(found.cutText).toEqual([])
  })

  test('flags the cut tab when the strip shows no fade on that edge', async ({ page }) => {
    const found = await at(
      page,
      1024,
      tabStrip('data-tab-strip data-fade-start="true" data-fade-end="false"')
    )
    expect(found.cutText.join('\n')).toMatch(/text cut at a frame edge/)
  })

  test('flags the cut tab when the marked strip clips instead of scrolling', async ({ page }) => {
    // A stale fade flag on a strip nobody can swipe is no excuse.
    const found = await at(page, 1024, tabStrip('data-tab-strip data-fade-end="true"', 'hidden'))
    expect(found.cutText.join('\n')).toMatch(/text cut at a frame edge/)
  })

  test('flags a cut label in an unmarked scroller', async ({ page }) => {
    const found = await at(page, 1024, tabStrip('data-fade-end="true"'))
    expect(found.cutText.join('\n')).toMatch(/text cut at a frame edge/)
  })
})

const list = (toolbar: string) => `<main style="width:1000px">
  <div role="tablist"><button role="tab">Assigned</button><button role="tab">Watching</button></div>
  ${toolbar}
  <table style="width:100%"><tbody><tr><td>Finding one</td><td>High</td></tr></tbody></table>
</main>`
const SEARCH =
  '<div style="display:flex;gap:8px"><input style="width:600px" placeholder="Search"><button>Filters</button></div>'

test.describe('layout matrix detector: wasted row', { tag: ['@shell'] }, () => {
  test('flags a row holding only "Updated ..."', async ({ page }) => {
    const found = await at(
      page,
      1024,
      list(`<div><span>Updated 2 minutes ago</span></div>${SEARCH}`)
    )
    expect(found.wastedRow.join('\n')).toMatch(/row of its own.*Updated 2 minutes ago/)
  })

  test('flags a row holding only "Top 5 of 40"', async ({ page }) => {
    const found = await at(page, 1024, list(`${SEARCH}<p>Top 5 of 40</p>`))
    expect(found.wastedRow.join('\n')).toMatch(/Top 5 of 40/)
  })

  test('flags a row holding one small control', async ({ page }) => {
    const found = await at(page, 1024, list(`${SEARCH}<div><button>Refresh</button></div>`))
    expect(found.wastedRow.join('\n')).toMatch(/Refresh/)
  })

  test('flags a caption with a lone Refresh button above an empty state', async ({ page }) => {
    const found = await at(
      page,
      820,
      `<main style="width:700px">
        <div role="tablist"><button role="tab">Assigned to me</button></div>
        <div style="display:flex;justify-content:space-between"><p>Open findings assigned to you, the nearest deadline first.</p><button aria-label="Refresh">R</button></div>
        <div style="display:flex;justify-content:space-between"><button>SLA due in 72 hours</button><button aria-label="Filters">F</button></div>
        <div style="height:280px;border:1px solid">Nothing is assigned to you</div>
      </main>`
    )
    expect(found.wastedRow.join('\n')).toMatch(/Open findings assigned to you.*Refresh/)
    expect(found.wastedRow.join('\n')).not.toMatch(/SLA due/)
  })

  test("is quiet for a dialog's title and description", async ({ page }) => {
    // The New finding dialog at 390 and 1440 px: its header's one-line
    // description was read as a wasted row.
    const found = await at(
      page,
      1440,
      `<main style="width:600px">
        <div data-slot="dialog-header"><h2>New finding</h2><p>Manually create a security finding.</p></div>
        <div style="display:flex;gap:8px"><input style="width:500px" placeholder="Title"></div>
        <div style="height:280px;border:1px solid">Form</div>
      </main>`
    )
    expect(found.wastedRow).toEqual([])
  })

  test('is quiet for the labels of a form in a dialog', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 900 })
    await page.setContent(
      doc(`<div role="dialog" style="width:360px">
        <div data-slot="dialog-header"><h2>New finding</h2></div>
        <label>Asset *</label><div><button style="width:330px">Pick an asset</button></div>
        <label>Title *</label><input style="width:330px">
        <p>The finding will be created with status New.</p>
        <textarea style="width:330px;height:140px"></textarea>
      </div>`)
    )
    const found = await findMatrixBreaks(page, { scope: '[role=dialog]' })
    expect(found.wastedRow).toEqual([])
  })

  test('is quiet for one toolbar row with the meta at its end', async ({ page }) => {
    const found = await at(
      page,
      1024,
      list(
        '<div style="display:flex;justify-content:space-between"><input style="width:600px" placeholder="Search"><span>Updated 2 minutes ago</span></div>'
      )
    )
    expect(found.wastedRow).toEqual([])
  })
})

const primary = (name: string, href?: string) =>
  href
    ? `<a data-slot="button" data-variant="default" href="${href}">${name}</a>`
    : `<button data-slot="button" data-variant="default">${name}</button>`

test.describe('layout matrix detector: duplicate main action', { tag: ['@shell'] }, () => {
  test('flags two primary buttons with one name', async ({ page }) => {
    const found = await at(
      page,
      1440,
      `<main>${primary('Add asset')}<div>${primary('Add asset')}</div></main>`
    )
    expect(found.duplicateAction.join('\n')).toMatch(/2 primary buttons "add asset"/)
  })

  test('flags two primary links to one target', async ({ page }) => {
    const found = await at(
      page,
      1440,
      `<main>${primary('New scan', '/scans/new')}${primary('Start scanning', '/scans/new')}</main>`
    )
    expect(found.duplicateAction.join('\n')).toMatch(/to \/scans\/new/)
  })

  test('is quiet for one primary and a secondary with the same name', async ({ page }) => {
    const found = await at(
      page,
      1440,
      `<main>${primary('Add asset')}<button data-slot="button" data-variant="outline">Add asset</button></main>`
    )
    expect(found.duplicateAction).toEqual([])
  })
})

test.describe('layout matrix detector: wide-screen stretch', { tag: ['@shell'] }, () => {
  const wide = `<main style="width:1800px">
    <input style="width:100%" placeholder="Search everything">
    <p>${'A long description that keeps going across the screen. '.repeat(12)}</p>
    <div style="display:grid;grid-template-columns:1fr 300px">
      <section><span>Short content</span></section><aside><button>Watch</button></aside>
    </div></main>`

  test('flags a stretched field, a long text line and a far rail at 1920 px', async ({ page }) => {
    const found = await at(page, 1920, wide)
    const lines = found.wideStretch.join('\n')
    expect(lines).toMatch(/field \d+px wide: "Search everything"/)
    expect(lines).toMatch(/text line \d+px wide/)
    expect(lines).toMatch(/rail \d+px from its content/)
  })

  test('is quiet on a 1440 px screen', async ({ page }) => {
    expect((await at(page, 1440, wide)).wideStretch).toEqual([])
  })

  test('is quiet for a capped layout at 1920 px', async ({ page }) => {
    const found = await at(
      page,
      1920,
      `<main style="max-width:900px;margin:auto"><input style="width:100%" placeholder="Search">
       <div style="display:grid;grid-template-columns:1fr 300px"><section><p>${'Content text '.repeat(40)}</p></section><aside><button>Watch</button></aside></div></main>`
    )
    expect(found.wideStretch).toEqual([])
  })

  test('is quiet for a bar list: the bar between a label and its value', async ({ page }) => {
    // The dashboard's category bars (bar-viz) at 1920 px: label, bar, value.
    const row = (
      w: number
    ) => `<div style="display:grid;grid-template-columns:9rem 1fr auto;gap:8px">
      <span>Service</span><span style="height:12px;background:#ddd"><span style="display:block;height:100%;width:${w}%;background:#36c"></span></span><span>2,840</span></div>`
    const found = await at(page, 1920, `<main style="width:1800px">${row(100)}${row(5)}</main>`)
    expect(found.wideStretch).toEqual([])
  })
})

const toolbar = (gap: number) => `<main style="width:600px">
  <div style="display:flex;gap:${gap}px">
    <button aria-label="Filters" style="width:36px;height:36px">F</button>
    <div style="border:1px solid;flex:1;display:flex"><input placeholder="Search entries" style="border:0;flex:1"></div>
  </div></main>`

test.describe('layout matrix detector: joined controls', { tag: ['@shell'] }, () => {
  test('flags a button joined to the search box', async ({ page }) => {
    const found = await at(page, 390, toolbar(4))
    expect(found.joined.join('\n')).toMatch(
      /button 4px from a field: "Filters" \| "Search entries"/
    )
  })

  test('is quiet at the kit gap', async ({ page }) => {
    expect((await at(page, 390, toolbar(8))).joined).toEqual([])
  })

  test('flags two framed controls pressed together in a frameless group', async ({ page }) => {
    const found = await at(
      page,
      390,
      toolbar(0).replace(
        '<div style="display:flex;gap:0px">',
        '<div data-slot="search-group" style="display:flex;gap:0px">'
      )
    )
    expect(found.joined.join('\n')).toMatch(/button 0px from a field/)
  })

  test('is quiet inside one segmented group', async ({ page }) => {
    const found = await at(
      page,
      390,
      toolbar(0)
        .replace(
          '<div style="display:flex;gap:0px">',
          '<div role="group" style="display:flex;gap:0px;border:1px solid">'
        )
        .replace(
          '<div style="border:1px solid;flex:1;display:flex">',
          '<div style="flex:1;display:flex">'
        )
    )
    expect(found.joined).toEqual([])
  })
})

test('a display:contents wrapper is not a column', { tag: ['@shell'] }, async ({ page }) => {
  const found = await at(
    page,
    390,
    `<main style="width:360px"><div style="display:grid;grid-template-columns:1fr 1fr">
      <div style="display:contents"><button style="width:120px">Filters</button></div><span>x</span></div></main>`
  )
  expect(found.pastPanel).toEqual([])
})

test.describe('layout matrix detector: empty tail', { tag: ['@shell'] }, () => {
  // The full-page picture of /remediation/tasks/[id] grew by the height of its
  // boxed finding list: 10,800 px of page under a panel that ends near 770 px.
  const shell = (height: number) =>
    doc(`<div style="height:${height}px;background:#fff"><main id="content" style="height:100%">
      <section style="border:1px solid #ccc;padding:8px"><h2>Findings</h2>
        <div style="height:480px;overflow-y:auto"><div style="height:10000px"><p>Row 1</p></div></div>
      </section></main></div>`)

  test('flags a page far taller than its last content', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 6000 })
    await page.setContent(shell(6000))
    expect((await findEmptyTail(page, 900)).join('\n')).toMatch(/6000px tall/)
  })

  test('is quiet when the page fits the window', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.setContent(shell(900))
    expect(await findEmptyTail(page, 900)).toEqual([])
  })
})

test.describe('layout matrix: page-opened check', { tag: ['@shell'] }, () => {
  // The matrix compares the browser path with openedPath(<resolved url>).
  test('accepts an id route that opened on the id resolveRoute picked', () => {
    const url = '/assets/01a20891-5c1e-4d7a-9f00-000000000001?tab=overview#ports'
    expect(new URL('http://web:3000' + url).pathname).toBe(openedPath(url))
    expect(openedPath('/vulnerabilities/CVE-2024-3094')).toBe('/vulnerabilities/CVE-2024-3094')
  })

  test('still fails a page that was sent elsewhere', () => {
    const want = openedPath('/remediation/tasks/7b0c4b8e-0000-4000-8000-000000000002')
    expect('/login').not.toBe(want)
    expect('/remediation/tasks/[id]').not.toBe(want)
  })

  test('matches the encoding the browser reports', async ({ page }) => {
    await page.route('**/*', (r) =>
      r.fulfill({ body: '<!doctype html><p>ok</p>', contentType: 'text/html' })
    )
    const url = '/findings/a b?x=1'
    await page.goto('http://opened.test' + url)
    expect(new URL(page.url()).pathname).toBe(openedPath(url))
  })
})
