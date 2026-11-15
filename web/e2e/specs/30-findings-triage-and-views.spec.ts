import { test, expect } from '../fixtures/authenticated-page'

/**
 * Findings: Triage is the primary action (it opens triage mode), Priority and Finding are always
 * columns, columns and density are kept in the URL (and saved with a view), and
 * a view with changes shows the unsaved-changes dot. Needs no particular data.
 */

test.describe('Findings triage and view state', { tag: ['@findings'] }, () => {
  test('Triage is the one primary button and opens triage mode; Esc comes back', async ({
    page,
  }) => {
    await page.goto('/findings?severity=critical')
    const triage = page.getByRole('button', { name: /^Triage/ })
    await expect(triage).toBeVisible({ timeout: 20_000 })
    await triage.click()
    await expect(page).toHaveURL(/\/findings\/triage\?status=new/)
    await expect(page.getByTestId('triage-top-bar')).toContainText('Needs triage')
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur())
    await page.keyboard.press('Escape')
    await expect(page).toHaveURL(/\/findings\?severity=critical$/)
  })

  test('Priority and Finding stay when other columns are hidden', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings?columns=')
    await expect(page.getByRole('columnheader', { name: 'Title' })).toBeVisible({ timeout: 20_000 })
    await expect(page.getByRole('columnheader', { name: 'Priority' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Status' })).toHaveCount(0)
  })

  test('hiding a column through View is kept in the URL and survives a reload', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings?status=new&state=all')
    await page.getByRole('button', { name: /^display: density/i }).click()
    await page.getByRole('menuitemcheckbox', { name: 'Status' }).click()
    await expect(page).toHaveURL(/columns=/)
    await page.keyboard.press('Escape')
    await page.reload()
    await expect(page.getByRole('columnheader', { name: 'Status' })).toHaveCount(0)
  })

  test('columns drop by width so the title keeps 280; the title is a link; Priority is sorted at rest', async ({
    page,
  }) => {
    const expected: Record<number, { shown: string[]; dropped: string[] }> = {
      1600: { shown: ['Severity', 'Signals and EPSS', 'Due / SLA'], dropped: [] },
      1440: { shown: ['Signals and EPSS', 'Due / SLA'], dropped: ['Severity'] },
      1280: { shown: ['Due / SLA'], dropped: ['Severity', 'Signals and EPSS'] },
      1024: { shown: [], dropped: ['Severity', 'Signals and EPSS', 'Due / SLA'] },
    }
    for (const [width, cols] of Object.entries(expected)) {
      await page.setViewportSize({ width: Number(width), height: 900 })
      await page.goto('/findings')
      const title = page.getByRole('columnheader', { name: 'Title' })
      await expect(title).toBeVisible({ timeout: 20_000 })
      const link = page.locator('[data-slot="finding-title-link"]').first()
      if (!(await link.isVisible().catch(() => false))) continue // no findings on this stack
      for (const name of cols.shown)
        await expect(page.getByRole('columnheader', { name }), `${name} at ${width}`).toHaveCount(1)
      for (const name of cols.dropped)
        await expect(page.getByRole('columnheader', { name }), `${name} at ${width}`).toHaveCount(0)
      const w = await title.evaluate((th) => th.getBoundingClientRect().width)
      expect(w, `title at ${width}`).toBeGreaterThanOrEqual(279)
      await expect(link).toHaveAttribute('href', /^\/findings\/[^/]+$/)
      await expect(page.getByRole('columnheader', { name: 'Priority' })).toHaveAttribute(
        'aria-sort',
        'descending'
      )
    }
  })

  test('rows are one line at the kit heights (40, 32 compact, 52 comfortable); the Priority header is not cut', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1600, height: 900 })
    await page.goto('/findings')
    // The person's density (Display menu) is kept in the browser under its stored word.
    for (const [density, height] of [
      ['comfortable', 40],
      ['compact', 32],
      ['spacious', 52],
    ] as const) {
      await page.evaluate((d) => localStorage.setItem('openctem:table-density', d), density)
      await page.reload()
      await expect(page.getByRole('columnheader', { name: 'Title' })).toBeVisible({
        timeout: 20_000,
      })
      if (!(await page.locator('[data-slot="finding-title-link"]').first().isVisible())) return
      const heights = await page
        .locator('main tbody tr')
        .evaluateAll((rows) => rows.map((tr) => Math.round(tr.getBoundingClientRect().height)))
      // Every density exact, compact included (the row menu trigger is dense).
      expect(new Set(heights), `rows at ${density}`).toEqual(new Set([height]))
      const cut = await page
        .getByRole('columnheader', { name: 'Priority' })
        .locator('[data-slot="sort-button"] span')
        .evaluate((s) => s.scrollWidth > s.clientWidth)
      expect(cut, 'Priority header label cut').toBe(false)
    }
  })

  test('frozen start columns: header and body cells stay together; the row menu scrolls in last', async ({
    page,
  }) => {
    for (const width of [1440, 1280, 1024]) {
      await page.setViewportSize({ width, height: 900 })
      // Every column turned on, so the table is wider than its frame.
      await page.goto('/findings?columns=severity,asset,source,status,slaStatus,createdAt')
      await expect(page.getByRole('columnheader', { name: 'Title' })).toBeVisible({
        timeout: 20_000,
      })
      if (!(await page.locator('[data-slot="finding-title-link"]').first().isVisible())) return
      const frame = page.locator('main [data-slot="table-container"]')
      const read = () =>
        frame.evaluate((f) => {
          const ths = [...f.querySelectorAll('thead th')]
          const tds = [...(f.querySelector('tbody tr')?.children ?? [])]
          const frozen = tds
            .map((td, i) => ({ td, th: ths[i] }))
            .filter(({ td }) => getComputedStyle(td).position === 'sticky')
            .map(({ td, th }) => ({
              th: Math.round(th.getBoundingClientRect().left),
              td: Math.round(td.getBoundingClientRect().left),
            }))
          const fr = f.getBoundingClientRect()
          const last = ths[ths.length - 1].getBoundingClientRect()
          const head = f.querySelector('thead')!.getBoundingClientRect()
          const row = f.querySelector('tbody tr')!.getBoundingClientRect()
          return {
            frozen,
            wide: f.scrollWidth > f.clientWidth + 1,
            lastInside: last.left >= fr.left - 1 && last.right <= fr.left + f.clientWidth + 1,
            rowClear: row.top >= head.bottom - 1,
          }
        })
      const rest = await read()
      expect(rest.rowClear, `first row clear of the header at ${width}`).toBe(true)
      expect(rest.frozen.length, `frozen columns at ${width}`).toBeGreaterThanOrEqual(2)
      for (const c of rest.frozen) expect(c.th, `header x = body x at ${width}`).toBe(c.td)
      if (!rest.wide) continue
      await frame.evaluate((f) => (f.scrollLeft = 200))
      const mid = await read()
      for (const [i, c] of mid.frozen.entries()) {
        expect(c.th, `header x = body x after a scroll at ${width}`).toBe(c.td)
        expect(c.td, `frozen column ${i} stays put at ${width}`).toBe(rest.frozen[i].td)
      }
      await frame.evaluate((f) => (f.scrollLeft = f.scrollWidth))
      const end = await read()
      expect(end.lastInside, `row menu column inside the frame at max scroll, ${width}`).toBe(true)
    }
  })

  test('there is no page-level horizontal scroll at 1024, 1280 and 1440', async ({ page }) => {
    for (const width of [1024, 1280, 1440]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/findings?columns=severity,asset,source,status,slaStatus,createdAt')
      await expect(page.getByTestId('findings-view-title')).toBeVisible({ timeout: 20_000 })
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth > document.documentElement.clientWidth
      )
      expect(overflow, `${width}px`).toBe(false)
    }
  })

  test('a practice with nothing yet says so in the table; nothing above the list; the view keeps its name', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    const top = async () => {
      const row = page.getByTestId('findings-toolbar-primary')
      await expect(row).toBeVisible({ timeout: 30_000 })
      return Math.round((await row.boundingBox())!.y)
    }
    await page.goto('/findings')
    await page.waitForLoadState('networkidle')
    const defaultTop = await top()
    const defaultTitle = await page.getByTestId('findings-view-title').textContent()

    await page.goto('/findings?practice=compliance')
    await page.waitForLoadState('networkidle')
    const empty = page.getByTestId('findings-empty-state')
    await expect(empty).toBeVisible({ timeout: 30_000 })
    // The seed has no compliance checks: the practice's first run, in the table.
    test.skip(
      (await empty.getAttribute('data-kind')) !== 'practice_nothing',
      'this stack has compliance findings'
    )
    await expect(empty).toContainText('No benchmark checks yet')
    await expect(page.getByTestId('compliance-benchmarks-panel')).toHaveCount(0)
    await expect(page.getByText('No findings match')).toHaveCount(0)
    // Choosing a practice is not a custom view.
    await expect(page.getByTestId('findings-view-title')).toHaveText(defaultTitle ?? '')
    // Nothing above the title row: the list starts where it does without a practice.
    expect(await top()).toBe(defaultTop)
  })
})
