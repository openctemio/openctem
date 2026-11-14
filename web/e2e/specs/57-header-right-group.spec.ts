import { test, expect } from '../fixtures/authenticated-page'
import { ICON_CONTRAST_FLOOR, iconContrast } from '../helpers/icon-contrast'

/**
 * The top bar to the shell package (0.2, 0.4): the right group in order
 * Create, Full screen, Approvals, Notifications, Theme, Account, every control
 * 32 x 32 with a 16 px icon in the ink colour (contrast >= 4.5:1 in light and
 * dark, as every icon-only control of the shell, sidebar and rail included), 4 px between them and 8 before the avatar; the
 * search trigger 420 wide from 1280 px, 200 from 1024 px and an icon-only
 * 32 px square below; the Create menu 232 wide with one-line 32 px rows, and
 * its "n" chords, which open the form once (Back and Forward do not reopen it).
 */

const SEARCH: [number, number][] = [
  [1440, 420],
  [1280, 420],
  [1024, 200],
  [900, 32],
  [768, 32],
]

for (const [width, search] of SEARCH) {
  for (const scheme of ['light', 'dark'] as const) {
    test(`header right group at ${width} in ${scheme}`, { tag: ['@shell'] }, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 })
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
      await page.goto('/findings')
      const group = page.locator('header [data-slot=header-actions]')
      await expect(group).toBeVisible()
      const m = await page.evaluate(() => {
        const header = document.querySelector('header')!
        const group = header.querySelector('[data-slot=header-actions]')!
        const controls = Array.from(group.querySelectorAll<HTMLElement>('button, a')).filter(
          (e) => e.getBoundingClientRect().width > 0
        )
        const boxes = controls.map((e) => e.getBoundingClientRect())
        const search = header.querySelector<HTMLElement>('button[aria-keyshortcuts]')!
        return {
          header: header.getBoundingClientRect().height,
          names: controls.map((e) => e.getAttribute('aria-label') ?? ''),
          sizes: boxes.map((b) => `${Math.round(b.width)}x${Math.round(b.height)}`),
          gaps: boxes.slice(1).map((b, i) => Math.round(b.left - boxes[i].right)),
          // The visible icon of each control (Theme hides one of sun / moon).
          icons: controls
            .map((e) =>
              Array.from(e.querySelectorAll('svg')).find((s) => s.getBoundingClientRect().width > 0)
            )
            .filter(Boolean)
            .map((s) => Math.round(s!.getBoundingClientRect().width)),
          search: Math.round(search.getBoundingClientRect().width),
          wraps: header.scrollHeight > header.clientHeight + 1,
        }
      })
      expect(m.header).toBe(48)
      expect(m.wraps).toBe(false)
      expect(new Set(m.sizes)).toEqual(new Set(['32x32']))
      expect(m.gaps.at(-1), 'before the avatar').toBe(8)
      expect(new Set(m.gaps.slice(0, -1))).toEqual(new Set([4]))
      expect(new Set(m.icons)).toEqual(new Set([16]))
      // Order: Create first, Theme then the account last (Full screen,
      // Approvals and Notifications depend on the browser and the role).
      expect(m.names[0]).toBe('Create')
      expect(m.names.at(-1)).toMatch(/^Open user menu/)
      expect(m.names.indexOf('Theme')).toBe(m.names.length - 2)
      expect(m.search).toBe(search)
      // Icons at rest (no hover): contrast >= 4.5:1 on the bar.
      await page.mouse.move(width / 2, 880)
      const icons = await iconContrast(
        page,
        'header [data-sidebar=trigger], header button[aria-keyshortcuts], header [data-slot=header-actions] button:not([aria-label^="Open user menu"]), header [data-slot=header-actions] a'
      )
      expect(icons.length).toBeGreaterThanOrEqual(4)
      for (const i of icons)
        expect(i.ratio, `${i.name}: ${i.icon} on ${i.background}`).toBeGreaterThanOrEqual(
          ICON_CONTRAST_FLOOR
        )
    })
  }
}

// The sidebar (1440) and the icon rail (900): toggle and row icons at rest.
for (const width of [1440, 900]) {
  for (const scheme of ['light', 'dark'] as const) {
    test(`sidebar icons at ${width} in ${scheme}`, { tag: ['@shell'] }, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 })
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
      await page.goto('/findings')
      await expect(page.locator('header [data-slot=header-actions]')).toBeVisible()
      await page.mouse.move(width - 10, 890)
      const icons = await iconContrast(
        page,
        '[data-sidebar=sidebar] [data-sidebar=trigger], [data-sidebar=sidebar] [data-sidebar=menu-button], [data-sidebar=sidebar] [data-sidebar=menu-sub-button]'
      )
      expect(icons.length).toBeGreaterThan(5)
      for (const i of icons)
        expect(i.ratio, `${i.name}: ${i.icon} on ${i.background}`).toBeGreaterThanOrEqual(
          ICON_CONTRAST_FLOOR
        )
    })
  }
}

test(
  'Create menu is 232 wide with one-line rows; "n a" opens Add asset once',
  { tag: ['@shell'] },
  async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    // No open animation: its zoom would scale the measured box.
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.goto('/findings')
    await page.getByRole('button', { name: 'Create' }).click()
    const menu = page.getByRole('menu')
    await expect(menu).toBeVisible()
    const m = await menu.evaluate((el) => ({
      width: (el as HTMLElement).offsetWidth,
      rows: Array.from(el.querySelectorAll<HTMLElement>('[role=menuitem]')).map(
        (r) => r.offsetHeight
      ),
    }))
    expect(m.width).toBe(232)
    expect(m.rows.length).toBeGreaterThan(0)
    expect(new Set(m.rows)).toEqual(new Set([32]))
    await page.keyboard.press('Escape')
    await expect(menu).toBeHidden()
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur())
    await page.keyboard.press('n')
    await page.keyboard.press('a')
    await expect(page).toHaveURL(/\/assets(\?|$)/)
    // The add menu (or the one type's form) opened, and the flag is consumed.
    await expect(page.getByRole('menu').or(page.getByRole('dialog')).first()).toBeVisible()
    await expect(page).not.toHaveURL(/new=asset/)
    await page.keyboard.press('Escape')
    // Back and Forward do not open it again.
    await page.goBack()
    await expect(page).toHaveURL(/\/findings/)
    await page.goForward()
    await expect(page).toHaveURL(/\/assets/)
    await page.waitForTimeout(800)
    await expect(page.getByRole('menu')).toHaveCount(0)
    await expect(page.getByRole('dialog')).toHaveCount(0)
  }
)

for (const locale of ['en', 'vi'] as const) {
  test(
    `no text in the header is clipped at 1024 in ${locale}`,
    { tag: ['@shell'] },
    async ({ page, baseURL }) => {
      await page.context().addCookies([{ name: 'locale', value: locale, url: baseURL! }])
      await page.setViewportSize({ width: 1024, height: 900 })
      await page.goto('/findings')
      await expect(page.locator('header [data-slot=header-actions]')).toBeVisible()
      const clipped = await page.evaluate(() =>
        Array.from(document.querySelectorAll<HTMLElement>('header span, header a, header li'))
          // Visible leaf text only (an sr-only name is a 1 px clipped box by design).
          .filter((e) => {
            const b = e.getBoundingClientRect()
            return b.width > 1 && b.height > 1 && e.children.length === 0
          })
          .filter((e) => e.scrollWidth > e.clientWidth + 1)
          // An ellipsis (truncate) is allowed; a hard clip is not.
          .filter((e) => getComputedStyle(e).textOverflow !== 'ellipsis')
          .map((e) => e.textContent)
      )
      expect(clipped).toEqual([])
      // The 200 px search shows the short label, whole.
      const label = page.locator('header button[aria-keyshortcuts] span').filter({ visible: true })
      await expect(label).toHaveText(locale === 'vi' ? 'Tìm kiếm' : 'Search')
      expect(await label.evaluate((e) => e.scrollWidth <= e.clientWidth)).toBe(true)
    }
  )
}
