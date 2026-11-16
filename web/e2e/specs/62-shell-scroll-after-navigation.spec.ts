import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * A page opened from the sidebar starts at its top: after a client navigation
 * between a list's quick views (the same route with other params), from a list
 * scrolled a little or a lot, and after a reload, the page title sits below the
 * app header, the page scroller is at 0 and nothing above it (the document, the
 * shell's columns) has scrolled. The framework scrolls the new page into view
 * with scrollIntoView, which moves every scrollable ancestor: the shell must
 * have no ancestor of the page scroller that can scroll.
 */

const LISTS = [
  { path: '/findings', views: /findings views/i },
  { path: '/assets', views: /asset views/i },
] as const

async function readShell(page: Page) {
  return page.evaluate(() => {
    const main = document.querySelector<HTMLElement>('main#content')!
    const header = document.querySelector('header')!
    const h1 = main.querySelector('h1')
    const scrolledAncestors: string[] = []
    for (let el = main.parentElement; el; el = el.parentElement) {
      if (el.scrollTop !== 0) scrolledAncestors.push(`${el.tagName} ${el.dataset.slot ?? ''}`)
    }
    return {
      doc: document.scrollingElement!.scrollTop,
      scroller: main.scrollTop,
      scrolledAncestors,
      headerBottom: header.getBoundingClientRect().bottom,
      titleTop: h1 ? h1.getBoundingClientRect().top : null,
    }
  })
}

function expectAtTop(s: Awaited<ReturnType<typeof readShell>>, what: string) {
  expect(s.doc, `document scroll after ${what}`).toBe(0)
  expect(s.scrolledAncestors, `scrolled shell ancestors after ${what}`).toEqual([])
  expect(s.scroller, `page scroller after ${what}`).toBe(0)
  expect(s.titleTop, `page title after ${what}`).not.toBeNull()
  expect(s.titleTop!, `page title below the app header after ${what}`).toBeGreaterThanOrEqual(
    s.headerBottom
  )
}

for (const list of LISTS) {
  test(
    `${list.path}: every quick view opens at the page top`,
    { tag: ['@shell'] },
    async ({ page }) => {
      await page.setViewportSize({ width: 1280, height: 800 })
      await page.emulateMedia({ reducedMotion: 'reduce' })
      await page.goto(list.path)
      const nav = page.getByRole('list', { name: list.views })
      await expect(nav).toBeVisible({ timeout: 30_000 })
      await page.waitForLoadState('networkidle')
      expectAtTop(await readShell(page), 'the first load')
      const links = nav.getByRole('link')
      const count = await links.count()
      for (const pre of [0, 30, 120, 400]) {
        for (let i = 0; i < count; i++) {
          const link = links.nth(i)
          const name = (await link.textContent())?.trim()
          await page.evaluate((y) => document.querySelector('main#content')?.scrollTo(0, y), pre)
          if (i % 2 === 0) {
            await link.click()
          } else {
            // The keyboard path: the same link, followed with Enter.
            await link.focus()
            await page.keyboard.press('Enter')
          }
          await expect(link).toHaveAttribute('aria-current', 'page')
          await page.waitForLoadState('networkidle')
          expectAtTop(await readShell(page), `${name} from ${pre} px`)
        }
      }
      await page.reload()
      await expect(nav).toBeVisible({ timeout: 30_000 })
      await page.waitForLoadState('networkidle')
      expectAtTop(await readShell(page), 'a reload')
    }
  )
}

/** The shell on a phone: nothing but the page scroller moves, sideways never. */
async function readPhoneShell(page: Page) {
  return page.evaluate(() => {
    const main = document.querySelector<HTMLElement>('main#content')!
    const header = document.querySelector('header')!
    const scrolledAncestors: string[] = []
    for (let el = main.parentElement; el; el = el.parentElement) {
      if (el.scrollTop !== 0 || el.scrollLeft !== 0) {
        scrolledAncestors.push(`${el.tagName} ${el.dataset.slot ?? ''}`)
      }
    }
    const se = document.scrollingElement!
    return {
      doc: se.scrollTop,
      sideways: se.scrollWidth > se.clientWidth || main.scrollWidth > main.clientWidth,
      scroller: main.scrollTop,
      scrolledAncestors,
      headerTop: header.getBoundingClientRect().top,
    }
  })
}

function expectShellStill(s: Awaited<ReturnType<typeof readPhoneShell>>, what: string) {
  expect(s.doc, `document scroll after ${what}`).toBe(0)
  expect(s.scrolledAncestors, `scrolled shell ancestors after ${what}`).toEqual([])
  expect(s.sideways, `horizontal scroll after ${what}`).toBe(false)
  expect(s.headerTop, `app header at the top after ${what}`).toBe(0)
}

/** A finger swipe up on the page: touch start, moves and end, as a phone sends them. */
async function swipeUp(page: Page, distance: number) {
  const cdp = await page.context().newCDPSession(page)
  const x = 195
  const y = 600
  await cdp.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x, y }] })
  for (let i = 1; i <= 10; i++) {
    await cdp.send('Input.dispatchTouchEvent', {
      type: 'touchMove',
      touchPoints: [{ x, y: y - (distance * i) / 10 }],
    })
    await page.waitForTimeout(16)
  }
  await cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] })
  await cdp.detach()
  await page.waitForTimeout(300)
}

test.describe('on a phone with touch', () => {
  test.use({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })

  for (const list of LISTS) {
    test(
      `${list.path}: the page scrolls in its scroller, views open at the top, the keyboard moves nothing else`,
      { tag: ['@shell', '@phone'] },
      async ({ page }) => {
        await page.emulateMedia({ reducedMotion: 'reduce' })
        await page.goto(list.path)
        await expect(page.locator('main h1')).toBeVisible({ timeout: 45_000 })
        await page.waitForLoadState('networkidle')
        expectAtTop(await readShell(page), 'the first load')
        expectShellStill(await readPhoneShell(page), 'the first load')

        // A swipe scrolls the page scroller (the clipped shell does not stop
        // it) and the header stays put.
        const scrollable = await page
          .locator('main#content')
          .evaluate((m) => m.scrollHeight > m.clientHeight + 40)
        if (scrollable) {
          await swipeUp(page, 300)
          const swiped = await readPhoneShell(page)
          expect(swiped.scroller, 'the page scroller moved with the swipe').toBeGreaterThan(0)
          expectShellStill(swiped, 'a swipe')
        }

        // Every quick view from the sidebar sheet, from a scrolled page.
        const trigger = page.locator('[data-sidebar="trigger"]').first()
        const drawer = page.locator('[data-mobile="true"]')
        const views = drawer.getByRole('list', { name: list.views })
        // The views arrive with their counts; a tap made while the page was
        // still settling is repeated.
        const openSheet = () =>
          expect(async () => {
            if (!(await drawer.isVisible())) await trigger.tap()
            await expect(views).toBeVisible({ timeout: 5_000 })
          }).toPass({ timeout: 45_000 })
        await openSheet()
        expectShellStill(await readPhoneShell(page), 'opening the sidebar sheet')
        const count = await views.getByRole('link').count()
        await page.keyboard.press('Escape')
        await expect(drawer).toBeHidden()
        for (let i = 0; i < count; i++) {
          await page.evaluate(() => document.querySelector('main#content')?.scrollTo(0, 200))
          await openSheet()
          const link = views.getByRole('link').nth(i)
          const name = (await link.textContent())?.trim()
          const href = await link.getAttribute('href')
          await link.tap()
          await page.waitForURL((u) => `${u.pathname}${u.search}` === href)
          await expect(drawer).toBeHidden()
          await page.waitForLoadState('networkidle')
          expectAtTop(await readShell(page), `${name} on a phone`)
          expectShellStill(await readPhoneShell(page), `${name} on a phone`)
        }

        // The finding detail opens over the page and closes back to it.
        if (list.path === '/findings') {
          const title = page.locator('[data-slot="finding-title-link"]').first()
          if (await title.isVisible().catch(() => false)) {
            await title.tap()
            const detail = page.getByRole('dialog')
            await expect(detail).toBeVisible()
            expectShellStill(await readPhoneShell(page), 'opening the finding detail')
            await page.keyboard.press('Escape')
            await expect(detail).toBeHidden()
            expectShellStill(await readPhoneShell(page), 'closing the finding detail')
          }
        }

        // The keyboard: the visual viewport shrinks while the search field has
        // the focus; only the page scroller may move to keep the field in view.
        const search = page.locator('main [data-slot="list-search-input"]').first()
        if (await search.isVisible().catch(() => false)) {
          await search.tap()
          await page.setViewportSize({ width: 390, height: 480 })
          await expect(search).toBeFocused()
          expectShellStill(await readPhoneShell(page), 'the keyboard opening')
          await search.blur()
          await page.setViewportSize({ width: 390, height: 844 })
          await page.evaluate(() => document.querySelector('main#content')?.scrollTo(0, 0))
          expectAtTop(await readShell(page), 'the keyboard closing')
          expectShellStill(await readPhoneShell(page), 'the keyboard closing')
        }
      }
    )
  }
})
