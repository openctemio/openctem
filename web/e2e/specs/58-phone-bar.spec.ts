import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { ICON_CONTRAST_FLOOR, iconContrast } from '../helpers/icon-contrast'

/**
 * The phone bar and drawer to the shell package (C2, 0.3, D19), below 768 px:
 *   - bar 48 tall, padding 0 8; toggle | separator 1 x 24 | Search, Approvals,
 *     Notifications, Account: every control 36 x 36, icon 20 (stroke 1.75) in
 *     the ink colour, contrast >= 4.5:1 in light and dark, 8 apart;
 *   - every control answers touches in a 44 x 44 square around it, and no two
 *     of those squares overlap;
 *   - Create, Full screen and Theme are not in the bar; Theme is in the account
 *     menu (a label and Light / Dark / System rows of 44, above Sign out);
 *   - the drawer: 288 wide, "Close sidebar" 36 with a 44 touch square, org
 *     trigger and nav rows 44 with 16/24 text and 16 px icons;
 *   - nothing scrolls sideways.
 * At 768 the desktop bar is back (32 px controls, Theme in the bar).
 */

type Box = { x: number; y: number; w: number; h: number }

/** A control's box, its touch box (the ::before) and whether a touch at the touch box edges reaches it. */
async function measureBar(page: Page) {
  return page.evaluate(() => {
    const header = document.querySelector('header')!
    const vis = (e: Element) => {
      const b = e.getBoundingClientRect()
      return b.width > 0 && b.height > 0
    }
    const controls = [
      header.querySelector('[data-sidebar=trigger]'),
      header.querySelector('button[aria-keyshortcuts]'),
      ...header.querySelectorAll('[data-slot=header-actions] button, [data-slot=header-actions] a'),
    ].filter((e): e is HTMLElement => !!e && vis(e))
    const reaches = (e: HTMLElement, x: number, y: number) => {
      const hit = document.elementFromPoint(x, y)
      return !!hit && (hit === e || e.contains(hit))
    }
    return {
      header: Math.round(header.getBoundingClientRect().height),
      pad: getComputedStyle(header.firstElementChild!).paddingInlineStart,
      separator: (() => {
        const s = header.querySelector<HTMLElement>('[data-slot=separator]')
        if (!s || !vis(s)) return null
        const b = s.getBoundingClientRect()
        return `${Math.round(b.width)}x${Math.round(b.height)}`
      })(),
      controls: controls.map((e) => {
        const b = e.getBoundingClientRect()
        const p = getComputedStyle(e, '::before')
        // -translate-y-1/2 is the `translate` property (Tailwind 4), not `transform`.
        const tyTok =
          p.translate && p.translate !== 'none' ? (p.translate.split(' ')[1] ?? '0px') : '0px'
        const ty = tyTok.endsWith('%')
          ? (parseFloat(tyTok) * parseFloat(p.height)) / 100
          : parseFloat(tyTok)
        // From 768 px a button has no touch extension: its box is its touch area.
        const touch =
          p.position === 'absolute'
            ? {
                x: b.x + parseFloat(p.left),
                y: b.y + parseFloat(p.top) + ty,
                w: parseFloat(p.width),
                h: parseFloat(p.height),
              }
            : { x: b.x, y: b.y, w: b.width, h: b.height }
        const icon = [...e.querySelectorAll('svg')].find(vis)
        return {
          name: e.getAttribute('aria-label') ?? e.textContent?.trim() ?? '',
          box: { x: b.x, y: b.y, w: b.width, h: b.height },
          touch,
          icon: icon ? Math.round(icon.getBoundingClientRect().width) : null,
          // A touch 1 px inside each edge of the 44 square lands on the control.
          edges: [
            reaches(e, touch.x + 1, b.y + b.height / 2),
            reaches(e, touch.x + touch.w - 1, b.y + b.height / 2),
            reaches(e, b.x + b.width / 2, touch.y + 1),
            reaches(e, b.x + b.width / 2, touch.y + touch.h - 1),
          ].every(Boolean),
        }
      }),
      scrollX: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    }
  })
}

const overlap = (a: Box, b: Box) =>
  Math.max(0, Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x)) *
  Math.max(0, Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y))

for (const width of [360, 390, 414, 767]) {
  for (const scheme of ['light', 'dark'] as const) {
    test(`phone bar at ${width} in ${scheme}`, { tag: ['@shell', '@phone'] }, async ({ page }) => {
      await page.setViewportSize({ width, height: 800 })
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
      await page.goto('/findings')
      await expect(page.locator('header [data-slot=header-actions]')).toBeVisible()
      const m = await measureBar(page)
      expect(m.header).toBe(48)
      expect(m.pad).toBe('8px')
      expect(m.separator).toBe('1x24')
      expect(m.scrollX, 'no sideways scroll').toBeLessThanOrEqual(0)
      const names = m.controls.map((c) => c.name)
      expect(names[0]).toBe('Open sidebar')
      expect(names.at(-1)).toMatch(/^Open user menu/)
      expect(names).not.toContain('Create')
      expect(names).not.toContain('Theme')
      expect(names.some((n) => /full screen/i.test(n))).toBe(false)
      for (const c of m.controls) {
        expect(`${Math.round(c.box.w)}x${Math.round(c.box.h)}`, c.name).toBe('36x36')
        expect(`${Math.round(c.touch.w)}x${Math.round(c.touch.h)}`, c.name).toBe('44x44')
        expect(c.edges, `${c.name}: touches at its 44 square's edges reach it`).toBe(true)
        if (c.icon !== null && !/^Open user menu/.test(c.name)) expect(c.icon, c.name).toBe(20)
        expect(c.touch.x, `${c.name} touch area on screen`).toBeGreaterThanOrEqual(0)
        expect(c.touch.x + c.touch.w, `${c.name} touch area on screen`).toBeLessThanOrEqual(width)
      }
      // The right group: 8 apart; no two touch squares overlap anywhere in the bar.
      const right = m.controls.slice(1)
      right.slice(1).forEach((c, i) => {
        expect(Math.round(c.box.x - (right[i].box.x + right[i].box.w)), c.name).toBe(8)
      })
      for (let i = 0; i < m.controls.length; i++)
        for (let j = i + 1; j < m.controls.length; j++)
          expect(
            overlap(m.controls[i].touch, m.controls[j].touch),
            `${m.controls[i].name} / ${m.controls[j].name}`
          ).toBe(0)
      // Icons at rest (no hover): 20 px, contrast >= 4.5:1 on the bar.
      await page.mouse.move(width / 2, 700)
      const icons = await iconContrast(
        page,
        'header [data-sidebar=trigger], header button[aria-keyshortcuts], header [data-slot=header-actions] button:not([aria-label^="Open user menu"]), header [data-slot=header-actions] a'
      )
      expect(icons.length).toBeGreaterThanOrEqual(3)
      for (const i of icons) {
        expect(i.size, i.name).toBe(20)
        expect(i.ratio, `${i.name}: ${i.icon} on ${i.background}`).toBeGreaterThanOrEqual(
          ICON_CONTRAST_FLOOR
        )
      }
    })
  }
}

test(
  'phone account menu carries Theme above Sign out',
  { tag: ['@shell', '@phone'] },
  async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 800 })
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.goto('/findings')
    await page.getByRole('button', { name: /^Open user menu/ }).click()
    const menu = page.getByRole('menu')
    await expect(menu).toBeVisible()
    // The open animation scales the menu: measure once it has settled.
    await expect
      .poll(() => menu.evaluate((el) => Math.round(el.getBoundingClientRect().left)))
      .toBe(8)
    const m = await menu.evaluate((el) => {
      const b = el.getBoundingClientRect()
      const items = [...el.querySelectorAll<HTMLElement>('[role=menuitem]')]
      return {
        left: Math.round(b.left),
        right: Math.round(window.innerWidth - b.right),
        labels: items.map((i) => i.textContent?.trim() ?? ''),
        heights: [...new Set(items.map((i) => Math.round(i.getBoundingClientRect().height)))],
        theme: [...el.querySelectorAll('[data-slot=dropdown-menu-label]')].some(
          (l) => l.textContent?.trim() === 'Theme'
        ),
      }
    })
    expect(m.left, 'sheet 8 from the left edge').toBe(8)
    expect(m.right, 'sheet 8 from the right edge').toBe(8)
    expect(m.theme).toBe(true)
    expect(m.heights).toEqual([44])
    const signOut = m.labels.indexOf('Sign out')
    expect(m.labels.slice(signOut - 3, signOut)).toEqual(['Light', 'Dark', 'System'])
    await menu.getByRole('menuitem', { name: 'Dark' }).click()
    await expect(page.locator('html')).toHaveClass(/dark/)
  }
)

test(
  'phone drawer: Close sidebar, org trigger and rows',
  { tag: ['@shell', '@phone'] },
  async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 800 })
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.goto('/findings')
    await page.getByRole('button', { name: 'Open sidebar' }).click()
    const drawer = page.locator('[data-mobile="true"]')
    await expect(drawer).toBeVisible()
    await page.waitForTimeout(400)
    const m = await drawer.evaluate((d) => {
      const size = (e: Element | null) => {
        if (!e) return null
        const b = e.getBoundingClientRect()
        return `${Math.round(b.width)}x${Math.round(b.height)}`
      }
      const close = [...d.querySelectorAll<HTMLElement>('[data-sidebar=trigger]')].find(
        (e) => e.textContent?.trim() === 'Close sidebar'
      )
      const p = close && getComputedStyle(close, '::before')
      const org = d.querySelector('[data-testid=team-switcher-trigger]')
      const orgName = org?.querySelector('span.truncate')
      const rows = [...d.querySelectorAll<HTMLElement>('[data-sidebar=menu-button]')].filter(
        (e) => e.getBoundingClientRect().height > 0 && e !== org
      )
      return {
        width: Math.round(d.getBoundingClientRect().width),
        close: size(close ?? null),
        closeTouch: p
          ? `${Math.round(parseFloat(p.width))}x${Math.round(parseFloat(p.height))}`
          : null,
        org: org ? Math.round(org.getBoundingClientRect().height) : null,
        orgFont:
          orgName &&
          getComputedStyle(orgName).fontSize + '/' + getComputedStyle(orgName).lineHeight,
        rowHeights: [...new Set(rows.map((r) => Math.round(r.getBoundingClientRect().height)))],
        rowFonts: [
          ...new Set(
            rows.map((r) => `${getComputedStyle(r).fontSize}/${getComputedStyle(r).lineHeight}`)
          ),
        ],
        icons: [
          ...new Set(
            rows
              .map((r) => r.querySelector('svg'))
              .filter(Boolean)
              .map((s) => Math.round(s!.getBoundingClientRect().width))
          ),
        ],
      }
    })
    expect(m.width).toBe(288)
    expect(m.close).toBe('36x36')
    expect(m.closeTouch).toBe('44x44')
    expect(m.org).toBe(44)
    expect(m.orgFont).toBe('16px/24px')
    expect(m.rowHeights).toEqual([44])
    expect(m.rowFonts).toEqual(['16px/24px'])
    expect(m.icons).toEqual([16])
    await drawer.getByRole('button', { name: 'Close sidebar' }).click()
    await expect(drawer).toBeHidden()
  }
)

for (const scheme of ['light', 'dark'] as const) {
  test(
    `phone drawer icons are clearly visible in ${scheme}`,
    { tag: ['@shell', '@phone'] },
    async ({ page }) => {
      await page.setViewportSize({ width: 390, height: 800 })
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' })
      await page.goto('/findings')
      await page.getByRole('button', { name: 'Open sidebar' }).click()
      const drawer = page.locator('[data-mobile="true"]')
      await expect(drawer).toBeVisible()
      await page.waitForTimeout(400)
      await page.mouse.move(380, 790)
      // Close sidebar and every row icon, at rest, against the drawer.
      const icons = await iconContrast(
        page,
        '[data-mobile="true"] [data-sidebar=trigger], [data-mobile="true"] [data-sidebar=menu-button], [data-mobile="true"] [data-sidebar=menu-sub-button]'
      )
      expect(icons.length).toBeGreaterThan(5)
      for (const i of icons)
        expect(i.ratio, `${i.name}: ${i.icon} on ${i.background}`).toBeGreaterThanOrEqual(
          ICON_CONTRAST_FLOOR
        )
    }
  )
}

test('desktop bar is back at 768', { tag: ['@shell'] }, async ({ page }) => {
  await page.setViewportSize({ width: 768, height: 800 })
  await page.goto('/findings')
  await expect(page.locator('header [data-slot=header-actions]')).toBeVisible()
  const m = await measureBar(page)
  const names = m.controls.map((c) => c.name)
  expect(names).toContain('Theme')
  expect(names).toContain('Create')
  expect(new Set(m.controls.map((c) => `${Math.round(c.box.w)}x${Math.round(c.box.h)}`))).toEqual(
    new Set(['32x32'])
  )
  expect(m.scrollX, 'no sideways scroll').toBeLessThanOrEqual(0)
})
