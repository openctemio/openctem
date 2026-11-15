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
