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

  test('columns drop by width so the title keeps 240; the title is a link; Priority is sorted at rest', async ({
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
      expect(w, `title at ${width}`).toBeGreaterThanOrEqual(239)
      await expect(link).toHaveAttribute('href', /^\/findings\/[^/]+$/)
      await expect(page.getByRole('columnheader', { name: 'Priority' })).toHaveAttribute(
        'aria-sort',
        'descending'
      )
    }
  })

  test('spare width goes to a cut Location before it sits empty in Title (1440, 1366)', async ({
    page,
  }) => {
    for (const width of [1440, 1366]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/findings')
      const title = page.getByRole('columnheader', { name: 'Title' })
      await expect(title).toBeVisible({ timeout: 20_000 })
      if (!(await page.locator('[data-slot="finding-title-link"]').first().isVisible())) continue
      await page.waitForTimeout(300)
      const m = await page.evaluate(() => {
        const ths = Array.from(document.querySelectorAll('main thead th'))
        const idx = ths.findIndex((th) => /^(Location|Vị trí)/.test(th.textContent?.trim() ?? ''))
        const titleTh = ths.find((th) => /^(Title|Tiêu đề)/.test(th.textContent?.trim() ?? ''))
        const rows = Array.from(document.querySelectorAll('main tbody tr'))
        const cut = rows.filter((tr) => {
          const td = tr.children[idx] as HTMLElement | undefined
          const text = td?.querySelector<HTMLElement>('.truncate') ?? td
          return !!text && text.scrollWidth > text.clientWidth + 1
        }).length
        return {
          location: Math.round(ths[idx]?.getBoundingClientRect().width ?? 0),
          title: Math.round(titleTh?.getBoundingClientRect().width ?? 0),
          cut,
        }
      })
      test.info().annotations.push({ type: `columns at ${width}`, description: JSON.stringify(m) })
      expect(m.title, `title floor at ${width}`).toBeGreaterThanOrEqual(239)
      // A cut location is allowed only at its cap (280), never while the
      // frame has spare width it could take.
      if (m.cut > 0)
        expect(m.location, `location cut below its cap at ${width}`).toBeGreaterThanOrEqual(239)
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

  test('default columns fit the frame at scroll 0 with long values: the row menu and the Due chip whole', async ({
    page,
    baseURL,
  }) => {
    // Long values the seed may not have: a long title and location, KEV marks,
    // a 109-day and a 1500-day overdue SLA (the chip reads "999+" above 999).
    const day = 86_400_000
    await page.route(/\/api\/v1\/findings\?/, async (route) => {
      const response = await route.fetch()
      const body = await response.json()
      if (Array.isArray(body.data)) {
        body.data = body.data.map((f: Record<string, unknown>, i: number) => ({
          ...f,
          title: `Remote code execution in the request parser of a long component name ${i}`,
          cve_id: 'CVE-2024-123456',
          is_in_kev: true,
          sla_kev_capped: true,
          sla_status: 'overdue',
          sla_deadline: new Date(Date.now() - (i % 2 ? 1500 : 109) * day - 3_600_000).toISOString(),
          asset: {
            ...((f.asset as object) ?? {}),
            name: `very-long-host-name-${i}.internal.example.com`,
            is_internet_accessible: true,
            is_crown_jewel: true,
          },
          file_path: '/srv/applications/payments/service/handlers/checkout/deep/path.go',
        }))
      }
      await route.fulfill({ response, json: body })
    })
    for (const locale of ['en', 'vi'] as const) {
      await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
      for (const sidebar of ['true', 'false']) {
        await page.context().addCookies([{ name: 'sidebar_state', value: sidebar, url: baseURL! }])
        for (const width of [1440, 1366, 1280, 1024]) {
          await page.setViewportSize({ width, height: 900 })
          await page.goto('/findings')
          await expect(page.locator('main thead th').first()).toBeVisible({ timeout: 20_000 })
          if (!(await page.locator('[data-slot="finding-title-link"]').first().isVisible())) return
          const at = `${locale}, ${width}, sidebar ${sidebar === 'true' ? 'open' : 'collapsed'}`
          const box = await page.locator('main [data-slot="table-container"]').evaluate((f) => {
            const right = f.getBoundingClientRect().left + f.clientWidth
            const ths = [...f.querySelectorAll('thead th')]
            const rows = [...f.querySelectorAll('tbody tr')]
            const menus = rows.map((tr) => tr.lastElementChild!.querySelector('button'))
            const chips = [...f.querySelectorAll<HTMLElement>('tbody [data-slot="sla-due-chip"]')]
            return {
              scrollLeft: f.scrollLeft,
              wide: f.scrollWidth > f.clientWidth + 1,
              headerEnd: ths[ths.length - 1].getBoundingClientRect().right,
              rowEnd: rows[0].lastElementChild!.getBoundingClientRect().right,
              right,
              menusOut: menus.filter((b) => !b || b.getBoundingClientRect().right > right + 0.5)
                .length,
              chips: chips.length,
              chipsOut: chips.filter((c) => {
                const pill = c.querySelector<HTMLElement>('[data-slot="sla-countdown"]')
                const cell = c.closest('td')!.getBoundingClientRect()
                return (
                  c.getBoundingClientRect().right > cell.right + 0.5 ||
                  (pill !== null && pill.scrollWidth > pill.clientWidth + 0.5)
                )
              }).length,
            }
          })
          expect(box.scrollLeft, at).toBe(0)
          expect(box.wide, `default columns fit the frame, ${at}`).toBe(false)
          expect(box.menusOut, `row menus inside the frame, ${at}`).toBe(0)
          expect(Math.abs(box.headerEnd - box.rowEnd), `header end = row end, ${at}`).toBeLessThan(
            1
          )
          expect(box.chipsOut, `Due chips whole inside their cell, ${at}`).toBe(0)
        }
      }
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
