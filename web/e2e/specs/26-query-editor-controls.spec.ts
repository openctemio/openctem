import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * The list search field's Query mode on Findings: syntax help, expand and run
 * sit inside the field; the expanded editor opens over the list without
 * moving the toolbar, colours the text with readable colours in both themes,
 * runs on Enter and takes new lines on Shift+Enter; a query that chips cannot
 * show travels in the link (fq) and a reload brings it back. Needs
 * no particular data.
 */

async function openQueryMode(page: Page) {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/findings')
  await page.getByRole('button', { name: /^query$/i }).click()
  const box = page.getByRole('combobox', { name: /filter as query text/i })
  await expect(box).toBeEnabled({ timeout: 20_000 })
  return box
}

function luminance(rgb: string): number {
  const [r, g, b] = (rgb.match(/[\d.]+/g) ?? ['0', '0', '0']).slice(0, 3).map((v) => {
    const c = Number(v) / 255
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  })
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

function contrast(a: string, b: string): number {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p)
  return (x + 0.05) / (y + 0.05)
}

test.describe('Query editor controls', { tag: ['@findings'] }, () => {
  test('help, expand and run sit in the field; the expanded editor runs and folds back', async ({
    page,
  }) => {
    const box = await openQueryMode(page)
    const field = (await box.boundingBox())!
    const controls = page.locator('[data-slot="query-field-controls"]')
    const cb = (await controls.boundingBox())!
    expect(cb.x).toBeGreaterThanOrEqual(field.x)
    expect(cb.x + cb.width).toBeLessThanOrEqual(field.x + field.width)
    expect(cb.y).toBeGreaterThanOrEqual(field.y)
    expect(cb.y + cb.height).toBeLessThanOrEqual(field.y + field.height)
    // The Basic | Query switch is its own control before the field, 8 px apart.
    const sw = (await page.locator('[data-slot="list-search-mode"]:visible').boundingBox())!
    expect(Math.round(field.x - (sw.x + sw.width))).toBe(8)
    expect(Math.abs(sw.y + sw.height / 2 - (field.y + field.height / 2))).toBeLessThanOrEqual(1)

    // Help: the syntax and the person's own fields, from the schema already read.
    await page.getByRole('button', { name: /query syntax/i }).click()
    const help = page.locator('[data-slot="query-help"]')
    await expect(help).toContainText(/Enter runs the query/)
    await expect(help).toContainText('severity')
    await page.keyboard.press('Escape')

    // Expand: over the list, the toolbar (Views) does not move.
    const addFilter = page.getByRole('button', { name: /^views$/i })
    const before = (await addFilter.boundingBox())!
    // The text and the caret carry over into the expanded editor.
    await box.fill('severity>=high')
    await box.evaluate((el: HTMLInputElement) => el.setSelectionRange(3, 3))
    await page.getByRole('button', { name: /expand the editor/i }).click()
    const big = page.locator('[data-slot="query-editor-expanded"] textarea')
    await expect(big).toBeVisible()
    await expect(big).toBeFocused()
    await expect(big).toHaveValue('severity>=high')
    expect(await big.evaluate((el: HTMLTextAreaElement) => el.selectionStart)).toBe(3)
    // Its height grows in over 200 ms: measured once it has grown.
    await expect
      .poll(async () => (await big.boundingBox())!.height, { timeout: 2_000 })
      .toBeGreaterThanOrEqual(200)
    test.info().annotations.push({
      type: 'expanded editor',
      description: JSON.stringify(
        await page.evaluate(() =>
          Object.fromEntries(
            [
              ['editor', '[data-slot="query-editor-expanded"] textarea'],
              ['field', 'main [data-slot="list-search"]'],
              ['addFilter', 'main [data-slot="add-filter"]'],
            ].map(([k, sel]) => {
              const r = document.querySelector(sel)?.getBoundingClientRect()
              return [k, r && { x: r.x, y: r.y, w: r.width, h: r.height }]
            })
          )
        )
      ),
    })
    expect(await addFilter.boundingBox()).toEqual(before)

    // Colours: every kind readable (4.5:1) on the editor, light and dark.
    await big.fill('severity>=high -status:accepted OR tool="nuclei"')
    for (const theme of ['light', 'dark'] as const) {
      await page.evaluate(
        (t) => document.documentElement.classList.toggle('dark', t === 'dark'),
        theme
      )
      // Colours resolved by the browser (oklch, alpha) and composited on a
      // 1x1 canvas: every background from the page down, then the text.
      const pairs = await page.evaluate(() => {
        const canvas = document.createElement('canvas')
        canvas.width = canvas.height = 1
        const ctx = canvas.getContext('2d', { willReadFrequently: true })!
        const copy = document.querySelector('[data-slot="query-highlight"]')!
        const chain: string[] = []
        for (let el: Element | null = copy; el; el = el.parentElement)
          chain.unshift(getComputedStyle(el).backgroundColor)
        const paint = (colors: string[]) => {
          ctx.globalCompositeOperation = 'copy'
          ctx.fillStyle = '#ffffff'
          ctx.fillRect(0, 0, 1, 1)
          ctx.globalCompositeOperation = 'source-over'
          for (const c of colors) {
            ctx.fillStyle = c
            ctx.fillRect(0, 0, 1, 1)
          }
          const [r, g, b2] = ctx.getImageData(0, 0, 1, 1).data
          return `rgb(${r}, ${g}, ${b2})`
        }
        const bg = paint(chain)
        return [...copy.querySelectorAll('span')]
          .filter((s) => s.textContent?.trim())
          .map((s) => ({
            text: s.textContent,
            fg: paint([...chain, getComputedStyle(s).color]),
            bg,
          }))
      })
      expect(pairs.length).toBeGreaterThan(5)
      for (const p of pairs)
        expect(contrast(p.fg, p.bg), `${theme} ${p.text}`).toBeGreaterThanOrEqual(4.5)
    }
    await page.evaluate(() => document.documentElement.classList.remove('dark'))

    // Shift+Enter is a new line; Enter runs.
    await big.fill('severity=critical')
    await big.press('Shift+Enter')
    await big.pressSequentially('is_in_kev=true')
    await expect(big).toHaveValue('severity=critical\nis_in_kev=true')
    await big.press('Enter')
    await expect(page).toHaveURL(/is_in_kev=true/)

    // Escape folds the unchanged editor back to one line.
    await expect(big).toBeVisible()
    await big.press('Escape')
    await expect(page.locator('[data-slot="query-editor-expanded"]')).toHaveCount(0)
  })

  test('the mode is part of the link: a reload opens in Query mode with the text', async ({
    page,
  }) => {
    const box = await openQueryMode(page)
    await expect(page).toHaveURL(/[?&]mode=query/)
    await box.fill('is_in_kev=true OR severity=critical')
    await box.press('Enter')
    await expect(page).toHaveURL(/[?&]fq=/)
    const url = new URL(page.url())
    expect(url.searchParams.get('fq')).toContain('OR')
    expect(url.searchParams.get('mode')).toBe('query')
    // Never a filter: no request carries it.
    const listed: string[] = []
    page.on('request', (r) => {
      const u = new URL(r.url())
      if (u.pathname.startsWith('/api/v1/findings')) listed.push(u.search)
    })
    await page.goto(url.toString())
    const again = page.getByRole('combobox', { name: /filter as query text/i })
    await expect(again).toBeEnabled({ timeout: 20_000 })
    await expect(again).toHaveValue(/is_in_kev=true OR severity=critical/)
    await expect(again).not.toBeFocused()
    await expect(page.getByRole('button', { name: /^query$/i })).toHaveAttribute(
      'aria-pressed',
      'true'
    )
    await expect(page.getByTestId('filter-chip-advanced')).toHaveCount(0)
    await expect(page.getByTestId('filter-chip-unknown')).toHaveCount(0)
    expect(listed.length).toBeGreaterThan(0)
    expect(listed.filter((q) => /[?&]mode=/.test(q))).toEqual([])

    // Basic: the param goes; the same query shows as one Advanced chip.
    await page.getByRole('button', { name: /^basic$/i }).click()
    await expect(page).not.toHaveURL(/[?&]mode=/)
    const chip = page.getByTestId('filter-chip-advanced')
    await expect(chip).toContainText('OR', { timeout: 20_000 })
    // A Basic link with fq keeps the chip; the chip opens Query mode.
    await page.goto(page.url())
    await expect(chip).toContainText('OR', { timeout: 20_000 })
    await chip.getByRole('button').first().click()
    await expect(page).toHaveURL(/[?&]mode=query/)
    await expect(again).toHaveValue(/is_in_kev=true OR severity=critical/, { timeout: 20_000 })
  })

  test('a Query-mode link whose text the server refuses opens in Query mode with the problem', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings?mode=query&fq=' + encodeURIComponent('severity=bogus OR kev=true'))
    const box = page.getByRole('combobox', { name: /filter as query text/i })
    await expect(box).toBeEnabled({ timeout: 20_000 })
    await expect(box).toHaveValue(/severity=bogus OR kev=true/)
    await expect(box).toHaveAttribute('aria-invalid', 'true', { timeout: 20_000 })
    await expect(page.getByText(/Column \d+\./)).toBeVisible()
  })

  test('a saved view opens in the mode it was saved in', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings')
    const name = `e2e query view ${Date.now()}`
    const id = await page.evaluate(async (viewName) => {
      const res = await fetch('/api/v1/views', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          page: 'findings',
          name: viewName,
          query: 'severity=critical',
          page_params: { mode: 'query' },
        }),
      })
      const body = (await res.json()) as { id: string; page_params?: Record<string, string> }
      return { status: res.status, id: body.id, params: body.page_params }
    }, name)
    expect(id.status).toBe(201)
    expect(id.params).toEqual({ mode: 'query' })
    try {
      await page.getByRole('button', { name: /^views$/i }).click()
      await page.getByRole('menuitem', { name }).click()
      await expect(page).toHaveURL(new RegExp(`view=${id.id}`))
      await expect(page).toHaveURL(/[?&]mode=query/)
      const box = page.getByRole('combobox', { name: /filter as query text/i })
      await expect(box).toBeEnabled({ timeout: 20_000 })
      await expect(page.getByRole('button', { name: /^query$/i })).toHaveAttribute(
        'aria-pressed',
        'true'
      )
      // The view's own conditions stay the view's (applied by the server);
      // the field holds the filter laid on top of it, none here.
      await expect(box).toHaveValue('')
    } finally {
      await page.evaluate(async (viewId) => {
        await fetch(`/api/v1/views/${viewId}`, { method: 'DELETE', credentials: 'same-origin' })
      }, id.id)
    }
  })
})

test.describe('Query editor controls on a phone', { tag: ['@findings'] }, () => {
  test.use({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })
  for (const locale of ['en', 'vi'] as const) {
    test(`the expanded editor fits the screen, wraps, and opens no keyboard (390 touch, ${locale})`, async ({
      page,
      baseURL,
    }) => {
      await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
      await page.goto('/findings')
      await page.locator('[data-slot="list-search-mode"]:visible').click()
      const box = page.locator('[data-slot="list-search-query"] [role="combobox"]')
      await expect(box).toBeEnabled({ timeout: 20_000 })
      const field = (await box.boundingBox())!
      const controls = page.locator('[data-slot="query-field-controls"]')
      const cb = (await controls.boundingBox())!
      const sw = (await page.locator('[data-slot="list-search-mode"]:visible').boundingBox())!
      expect(cb.x).toBeGreaterThanOrEqual(field.x)
      expect(cb.x + cb.width).toBeLessThanOrEqual(field.x + field.width)
      // The mode toggle is outside the field, before it (and before Filters).
      expect(sw.x + sw.width).toBeLessThanOrEqual(field.x)
      // Only the overflow and Apply sit in the one-line field.
      await expect(controls.getByRole('button', { name: /query syntax|cú pháp/i })).toBeHidden()
      const apply = controls.locator('[data-slot="query-apply"]')
      expect((await apply.boundingBox())!.width).toBe(28)
      // The text keeps at least 55 % of the field at 375 px.
      await page.setViewportSize({ width: 375, height: 812 })
      const share = await box.evaluate((el: HTMLInputElement) => {
        // The text's box: the field less its borders and paddings (icons, controls).
        const cs = getComputedStyle(el)
        const width = el.getBoundingClientRect().width
        const text =
          width -
          parseFloat(cs.borderLeftWidth) -
          parseFloat(cs.borderRightWidth) -
          parseFloat(cs.paddingLeft) -
          parseFloat(cs.paddingRight)
        return text / width
      })
      expect(share).toBeGreaterThanOrEqual(0.55)
      await page.setViewportSize({ width: 390, height: 844 })
      await box.fill('severity>=high AND is_in_kev=true AND status!=accepted AND tool="nuclei"')
      // Edited: the Apply icon is filled.
      await expect(apply).toHaveClass(/bg-primary/)
      await box.blur()
      await controls
        .getByRole('button', { name: /more query options|thêm tùy chọn truy vấn/i })
        .tap()
      await page.getByRole('menuitem', { name: /expand the editor|mở rộng trình soạn/i }).tap()
      const big = page.locator('[data-slot="query-editor-expanded"] textarea')
      await expect(big).toBeVisible()
      await expect(big).not.toBeFocused()
      // Long text wraps: no sideways scroll; the editor stays on screen.
      expect(
        await big.evaluate((el: HTMLTextAreaElement) => el.scrollWidth <= el.clientWidth + 1)
      ).toBe(true)
      const room = await page.evaluate(() => window.visualViewport?.height ?? window.innerHeight)
      const eb = (await page.locator('[data-slot="query-editor-expanded"]').boundingBox())!
      expect(eb.y + eb.height).toBeLessThanOrEqual(room)
      expect(eb.x).toBeGreaterThanOrEqual(0)
      expect(eb.x + eb.width).toBeLessThanOrEqual(390)
    })
  }
})

test.describe(
  'The search mode in the link on every list',
  { tag: ['@findings', '@assets', '@scans'] },
  () => {
    for (const [path, name] of [
      ['/assets', /filter as query text/i],
      ['/scans', /filter scans as query text/i],
    ] as const) {
      test(`${path}?mode=query opens in Query mode; without it, Basic`, async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 900 })
        await page.goto(`${path}?mode=query`)
        const box = page.getByRole('combobox', { name })
        await expect(box).toBeVisible({ timeout: 20_000 })
        await expect(page.getByTestId('filter-chip-unknown')).toHaveCount(0)
        await page.getByRole('button', { name: /^basic$/i }).click()
        await expect(page).not.toHaveURL(/[?&]mode=/)
        await page.reload()
        await expect(page.getByRole('button', { name: /^basic$/i })).toHaveAttribute(
          'aria-pressed',
          'true',
          { timeout: 20_000 }
        )
        await expect(box).toHaveCount(0)
      })
    }
  }
)
