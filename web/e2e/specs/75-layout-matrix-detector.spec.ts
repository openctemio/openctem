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
 * Facts (a <dl>, a MetaLine of label and value, a bordered fact card) are not
 * wasted rows, and a field under a sticky action bar is not joined to it.
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

  // The run detail sheet at 390 px: stacked sections (Stages, Timeline)
  // above the task table. Only the table's own section is its toolbar.
  const sheet = (
    ownSection: string
  ) => `<div data-slot="sheet-content" role="dialog" style="width:380px">
      <div data-slot="sheet-header"><h2>Run 42</h2></div>
      <section><h3>Stages</h3><p>Discovery done</p><p>Ports done</p></section>
      <section><h3>Timeline</h3><p>Started 10:02</p><p>Finished 10:09</p></section>
      <section><h3>Tasks</h3>${ownSection}
        <table style="width:100%"><tbody><tr><td>nuclei</td><td>Done</td></tr></tbody></table>
      </section>
    </div>`

  test("flags a lone row inside an overlay table's own section", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 900 })
    await page.setContent(doc(sheet('<p>Updated 2 minutes ago</p>')))
    const found = await findMatrixBreaks(page, { scope: '[role=dialog]' })
    expect(found.wastedRow.join('\n')).toMatch(/Updated 2 minutes ago/)
    expect(found.wastedRow.join('\n')).not.toMatch(/Started|Discovery/)
  })

  test('ignores a wrapped facts line in a sheet header', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 900 })
    await page.setContent(
      doc(
        `<div data-slot="sheet-content" role="dialog" style="width:380px">
      <div data-slot="detail-header"><h2>Run 42</h2><span>Done</span>
        <p>Tasks 0/1 task</p><p>Duration 4m 12s</p><p>deadline in 1h 37m</p></div>
      <section>
        <table style="width:100%"><tbody><tr><td>nuclei</td><td>Done</td></tr></tbody></table>
      </section>
    </div>`
      )
    )
    const found = await findMatrixBreaks(page, { scope: '[role=dialog]' })
    expect(found.wastedRow).toEqual([])
  })

  test('is quiet for rows under another section heading in an overlay', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 900 })
    await page.setContent(doc(sheet('')))
    const found = await findMatrixBreaks(page, { scope: '[role=dialog]' })
    expect(found.wastedRow).toEqual([])
  })

  // Detail and entry pages: facts above the page's only table (console
  // /users/[userId], /organizations/[tenantId], /programs/[id]) or above the
  // first content block (/invitations) are content, not toolbar rows.
  const detail = (facts: string) => `<main style="width:1000px">
      <div data-slot="page-header"><h1>admin@example.com</h1></div>
      ${facts}
      <h2>Activity</h2>
      <table style="width:100%"><tbody><tr><td>Signed in</td><td>2 minutes ago</td></tr></tbody></table>
    </main>`

  test('is quiet for a <dl> fact grid on a detail page', async ({ page }) => {
    const found = await at(
      page,
      1024,
      detail(`<dl style="display:grid;grid-template-columns:1fr 1fr;gap:12px 24px;margin:0">
        <div><dt>Signs in with</dt><dd style="margin:0">Password</dd></div>
        <div><dt>Two-step verification</dt><dd style="margin:0">Off</dd></div>
        <div><dt>Last sign-in</dt><dd style="margin:0">1 minute ago</dd></div>
        <div><dt>Created</dt><dd style="margin:0">3 minutes ago</dd></div></dl>`)
    )
    expect(found.wastedRow).toEqual([])
  })

  test('is quiet for bordered fact cards side by side', async ({ page }) => {
    const card = (title: string, note: string) =>
      `<section data-slot="card" style="border:1px solid;border-radius:8px;padding:16px"><div>${title}</div><p style="margin:8px 0 0">${note}</p></section>`
    const found = await at(
      page,
      1024,
      detail(`<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        ${card('Organizations', 'Not a member of any organization.')}
        ${card('Linked identities', 'No identity provider is linked.')}</div>`)
    )
    expect(found.wastedRow).toEqual([])
  })

  test('is quiet for a MetaLine of label and value facts', async ({ page }) => {
    const found = await at(
      page,
      1024,
      detail(`<p data-slot="meta-line" style="display:flex;gap:12px">
        <span data-slot="meta-line-item">Platform <span class="text-foreground">bug bounty</span></span>
        <span data-slot="meta-line-item">Handle <span class="text-foreground">example-shop</span></span></p>
        <p data-slot="meta-line"><span data-slot="meta-line-item">Scope <span class="text-foreground">4 targets</span></span></p>`)
    )
    expect(found.wastedRow).toEqual([])
  })

  test('is quiet for an entry page: its header line and the organization card', async ({
    page,
  }) => {
    const found = await at(
      page,
      1024,
      `<main style="width:600px"><section data-slot="card" style="border:1px solid;padding:24px">
        <div data-slot="entry-header"><h1>Join Example Org</h1><div>A team member invited you to join Example Org.</div></div>
        <div style="border:1px solid;border-radius:8px;padding:12px;display:flex;gap:12px">
          <span>EO</span><div><p style="margin:0">Example Org</p><p style="margin:0">For invitee@example.com</p></div></div>
        <div style="height:160px;border:1px solid">What accepting gives</div>
      </section></main>`
    )
    expect(found.wastedRow).toEqual([])
  })

  test('still flags a lone label, a lone notice and a lone button beside fact cards', async ({
    page,
  }) => {
    const found = await at(
      page,
      1024,
      detail(`<dl style="margin:0"><dt>Created</dt><dd style="margin:0">3 minutes ago</dd></dl>
        <p data-slot="meta-line"><span data-slot="meta-line-item">Updated 2 minutes ago</span></p>
        <div role="status" style="border:1px solid;padding:8px">No session is active right now.</div>
        <div><button>Copy reset link</button></div>`)
    )
    const lines = found.wastedRow.join('\n')
    expect(lines).toMatch(/Updated 2 minutes ago/)
    expect(lines).toMatch(/No session is active right now/)
    expect(lines).toMatch(/Copy reset link/)
    expect(lines).not.toMatch(/Created/)
  })

  test('is quiet for score and exploit cards: a card title over a <dl>', async ({ page }) => {
    // /emerging-threats/[id]: the Score and Exploit status cards above the
    // affected assets table.
    const card = (title: string, rows: string) =>
      `<section data-slot="card" style="border:1px solid;padding:16px"><div data-slot="card-title">${title}</div>
        <dl style="display:grid;grid-template-columns:1fr auto;margin:0">${rows}</dl></section>`
    const found = await at(
      page,
      1024,
      detail(`<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        ${card('Score', '<dt>Severity</dt><dd style="margin:0">40</dd><dt>Total</dt><dd style="margin:0">87</dd>')}
        ${card('Exploit status', '<dt>Known exploited</dt><dd style="margin:0">Yes</dd><dt>EPSS</dt><dd style="margin:0">0.97</dd>')}</div>`)
    )
    expect(found.wastedRow).toEqual([])
  })

  test('still flags the lines of a bordered panel with fields', async ({ page }) => {
    // /programs/[id] notifications: a panel to attach a channel is a form,
    // not a card of facts.
    const found = await at(
      page,
      1024,
      detail(`<section style="border:1px solid;padding:16px"><p>No channel is attached.</p>
        <p>Alerts go to the channels below.</p><select><option>Pick a channel</option></select></section>`)
    )
    expect(found.wastedRow.join('\n')).toMatch(/No channel is attached/)
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

  // /pentest/findings/new from 768 to 1280 px: the form's sticky action bar
  // scrolls over a field; the field is not beside the bar's buttons.
  const underBar = (pinned: boolean) => `<main style="width:700px">
    <div style="height:60px"></div>
    <div style="${pinned ? 'position:sticky;top:0;' : ''}display:flex;justify-content:flex-end;gap:8px;height:40px;background:#fff">
      <button style="width:100px">Save draft</button></div>
    <div style="display:flex;justify-content:flex-end;margin-top:-30px">
      <input placeholder="Reference URL" style="width:200px;margin-right:104px"></div>
    <div style="height:1200px"></div></main>`

  test('flags a field pressed against a button in the same flow', async ({ page }) => {
    const found = await at(page, 1024, underBar(false))
    expect(found.joined.join('\n')).toMatch(/Save draft.*Reference URL/)
  })

  test('is quiet for a field passing under a sticky action bar', async ({ page }) => {
    expect((await at(page, 1024, underBar(true))).joined).toEqual([])
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

test(
  'a node of a zoomable canvas is not past its column',
  { tag: ['@shell'] },
  async ({ page }) => {
    // /scans/workflows/[id]: React Flow draws nodes past its pane when zoomed.
    const pane = (cls: string) => `<main style="width:900px">
    <div style="display:grid;grid-template-columns:600px 280px;gap:20px">
      <div class="${cls}" style="position:relative;height:300px"><div style="position:absolute;left:0;top:20px">
        <button style="width:900px;white-space:nowrap">Subdomain discovery</button></div></div>
      <aside><p>Palette</p></aside></div></main>`
    expect((await at(page, 1440, pane('canvas'))).pastPanel.join('\n')).toMatch(
      /Subdomain discovery/
    )
    expect((await at(page, 1440, pane('react-flow'))).pastPanel).toEqual([])
  }
)

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

const cut = (attrs: string, text: string, width = 90) =>
  `<span ${attrs} style="display:block;width:${width}px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${text}</span>`

test.describe('layout matrix detector: cut meaning', { tag: ['@shell'] }, () => {
  // /sensors 2026-11-25: "takes no new jo…" in the status column, and the vi
  // metric tile "mất kết nối, SDK, heart…".
  test('flags a status reason cut by its ellipsis, with the visible and full text', async ({
    page,
  }) => {
    const found = await at(
      page,
      390,
      `<main>${cut('data-slot="status-reason"', 'takes no new jobs')}</main>`
    )
    expect(found.cutMeaning.join('\n')).toMatch(
      /cut "takes no.*…" of "takes no new jobs" at span\[data-slot="status-reason"\]/
    )
  })

  test('flags a line clamp that hides lines', async ({ page }) => {
    const found = await at(
      page,
      390,
      `<main><p style="width:120px;display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2;overflow:hidden">${'mất kết nối, SDK, heartbeat cũ '.repeat(3)}</p></main>`
    )
    expect(found.cutMeaning.join('\n')).toMatch(/cut ".*…" of "mất kết nối, SDK, heartbeat cũ/)
  })

  test('is quiet for a text that fits, and for a cut with only a title', async ({ page }) => {
    expect((await at(page, 390, `<main>${cut('', 'Online', 200)}</main>`)).cutMeaning).toEqual([])
    // A title alone does not make a status reason readable at a glance.
    const titled = await at(
      page,
      390,
      `<main>${cut('title="takes no new jobs"', 'takes no new jobs')}</main>`
    )
    expect(titled.cutMeaning).toHaveLength(1)
  })

  const nameCell = (attrs: string) =>
    `<main><table><tbody><tr><td data-column-kind="name">${cut(attrs, 'payments-gateway.internal.example.com')}</td></tr></tbody></table></main>`

  test('is quiet for a name column cell whose full text is reachable', async ({ page }) => {
    expect(
      (await at(page, 1024, nameCell('title="payments-gateway.internal.example.com"'))).cutMeaning
    ).toEqual([])
    expect((await at(page, 1024, nameCell('data-slot="tooltip-trigger"'))).cutMeaning).toEqual([])
  })

  test('flags a name column cell with no tooltip, title or label', async ({ page }) => {
    const found = await at(page, 1024, nameCell(''))
    expect(found.cutMeaning.join('\n')).toMatch(/name column, no tooltip or title/)
  })

  test('honours data-cut-tooltip only with the full text reachable', async ({ page }) => {
    const withTip = `<main><button data-slot="tooltip-trigger">${cut('data-cut-tooltip', 'Last heartbeat 54 days ago')}</button></main>`
    expect((await at(page, 390, withTip)).cutMeaning).toEqual([])
    const without = `<main>${cut('data-cut-tooltip', 'Last heartbeat 54 days ago')}</main>`
    expect((await at(page, 390, without)).cutMeaning.join('\n')).toMatch(
      /marked data-cut-tooltip, no tooltip/
    )
  })

  test('reports a column of cut cells once, with the count', async ({ page }) => {
    const rows = Array.from(
      { length: 3 },
      () =>
        `<tr><td data-column="reason" data-column-kind="text">${cut('', 'last heartbeat 54d 12h ago')}</td></tr>`
    ).join('')
    const found = await at(page, 1024, `<main><table><tbody>${rows}</tbody></table></main>`)
    expect(found.cutMeaning).toHaveLength(1)
    expect(found.cutMeaning[0]).toMatch(/td\[data-column="reason"\] > span \(3 elements\)/)
  })
})
