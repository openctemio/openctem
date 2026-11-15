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
    // They end before the Basic | Query switch (its width is measured by the field).
    const sw = (await page.locator('[data-slot="list-search-mode"]:visible').boundingBox())!
    expect(cb.x + cb.width).toBeLessThanOrEqual(sw.x)

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
    expect((await big.boundingBox())!.height).toBeGreaterThanOrEqual(200)
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

  test('a query chips cannot show travels in the link and a reload brings it back', async ({
    page,
  }) => {
    const box = await openQueryMode(page)
    await box.fill('is_in_kev=true OR severity=critical')
    await box.press('Enter')
    await expect(page).toHaveURL(/[?&]fq=/)
    const url = page.url()
    const fq = new URL(url).searchParams.get('fq') ?? ''
    expect(fq).toContain('OR')
    await page.goto(url)
    // The link shows the query as one Advanced chip; it opens Query mode with the text.
    const chip = page.getByTestId('filter-chip-advanced')
    await expect(chip).toContainText('OR', { timeout: 20_000 })
    await chip.getByRole('button').first().click()
    const again = page.getByRole('combobox', { name: /filter as query text/i })
    await expect(again).toBeEnabled({ timeout: 20_000 })
    await expect(again).toHaveValue(/is_in_kev=true OR severity=critical/)
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
      expect(cb.x + cb.width).toBeLessThanOrEqual(sw.x)
      // Only the overflow and Apply sit in the one-line field (with the mode toggle).
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
