import fs from 'fs'
import path from 'path'
import type { Page } from '@playwright/test'
import { open } from '../helpers/page-anatomy'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * The scroll ends where the page ends, on EVERY page of the console, at 390px
 * and at 1440px.
 *
 * A page that can scroll stops a normal bottom padding after its last visible
 * content: the page scroller's scrollable height may exceed the bottom of the
 * last visible element by at most the page's own bottom padding plus 8px. Before,
 * a box nobody sees kept the scroll going: Program health's screen-reader table
 * (`sr-only` does not shrink a table) added a screen or more of empty background
 * below the last card, and a list's screen-reader status line, placed last in
 * its stack, left 16px under a table without a pager. Content inside a box that
 * clips it (overflow, `sr-only`) counts only as far as the clip shows it.
 *
 * The document itself never scrolls: the shell's page scroller is the one
 * scroller, so `document.scrollingElement` is never taller than the window.
 *
 * The routes are read from the app directory, so a new page is checked the day
 * it is added.
 */

const APP = path.resolve(__dirname, '../../src/app/(dashboard)')
const SLACK_PX = 8

/** Static routes of the dashboard shell, from its page files. */
function staticRoutes(): string[] {
  const out: string[] = []
  const walk = (dir: string, segs: string[]) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!e.isDirectory()) {
        if (e.name === 'page.tsx') out.push('/' + segs.filter(Boolean).join('/'))
        continue
      }
      if (e.name.startsWith('_') || e.name === '__tests__' || e.name.startsWith('@')) continue
      const seg = /^\(.*\)$/.test(e.name) ? '' : e.name
      walk(path.join(dir, e.name), [...segs, seg])
    }
  }
  walk(APP, [])
  return [...new Set(out)].filter((r) => !r.includes('[')).sort()
}

export type ScrollEnd = {
  /** How far the page scroller's scroll goes past its last visible content, less its padding. */
  excess: number
  scrollHeight: number
  clientHeight: number
  contentBottom: number
  padding: number
  /** The element whose box reaches furthest down in the scroller, when that is not visible content. */
  deepest: string
  /** How far the document scrolls on its own (0 in the shell). */
  documentExcess: number
}

/** Measures how far the page scrolls past its last visible content. */
export async function measureScrollEnd(page: Page): Promise<ScrollEnd> {
  return page.evaluate(() => {
    const main = document.querySelector<HTMLElement>('main#content')!
    const box = main.getBoundingClientRect()
    const toContent = (y: number) => y - box.top + main.scrollTop
    const describe = (el: Element) => {
      const h = el as HTMLElement
      const cls = typeof h.className === 'string' ? h.className.trim().split(/\s+/).slice(0, 4) : []
      const slot = h.dataset?.slot ? `[data-slot=${h.dataset.slot}]` : ''
      return `${el.tagName.toLowerCase()}${slot}${cls.length ? '.' + cls.join('.') : ''}`
    }
    const visible = (s: CSSStyleDeclaration, r: DOMRect) =>
      r.width >= 2 && r.height >= 2 && s.visibility !== 'hidden' && Number(s.opacity) !== 0
    // Visible content: text, media, form controls and painted boxes.
    const paints = (el: Element, s: CSSStyleDeclaration) => {
      if (/^(IMG|SVG|CANVAS|VIDEO|INPUT|TEXTAREA|SELECT|BUTTON|svg)$/.test(el.tagName)) return true
      for (const n of el.childNodes)
        if (n.nodeType === Node.TEXT_NODE && n.textContent!.trim()) return true
      if (s.backgroundColor !== 'rgba(0, 0, 0, 0)' && s.backgroundColor !== 'transparent')
        return true
      if (parseFloat(s.borderBottomWidth) > 0 && s.borderBottomStyle !== 'none') return true
      if (parseFloat(s.borderTopWidth) > 0 && s.borderTopStyle !== 'none') return true
      return s.boxShadow !== 'none'
    }
    let contentBottom = 0
    let deepestBottom = 0
    let deepest = ''
    // `clip` is the bottom (in scroll content coordinates) below which an
    // ancestor clips what it holds: overflow other than visible, or the
    // clip of screen-reader text (sr-only), which shows nothing at all.
    const walk = (el: Element, clip: number) => {
      const s = getComputedStyle(el)
      if (s.display === 'none') return
      // A fixed box (a bar, a sheet) is outside the scroll.
      if (s.position === 'fixed') return
      const r = el.getBoundingClientRect()
      const top = toContent(r.top)
      const bottom = toContent(r.bottom)
      if (r.height > 0 && bottom > deepestBottom) {
        deepestBottom = bottom
        deepest = describe(el)
      }
      const hidden = s.clip === 'rect(0px, 0px, 0px, 0px)' || s.clipPath === 'inset(50%)'
      if (!hidden && top < clip && visible(s, r) && paints(el, s))
        contentBottom = Math.max(contentBottom, Math.min(bottom, clip))
      let inner = clip
      if (hidden) inner = -Infinity
      else if (s.overflowY !== 'visible') inner = Math.min(clip, bottom)
      for (const c of el.children) walk(c, inner)
    }
    for (const c of main.children) walk(c, Infinity)
    // The page's own bottom padding: the first block of the scroller (the
    // page's <Main>) and the scroller's own.
    const first = main.firstElementChild as HTMLElement | null
    const padding =
      parseFloat(getComputedStyle(main).paddingBottom) +
      (first ? parseFloat(getComputedStyle(first).paddingBottom) : 0)
    const scrollHeight = main.scrollHeight
    const clientHeight = main.clientHeight
    const scrolls = scrollHeight > clientHeight + 1
    const doc = document.scrollingElement!
    return {
      excess: scrolls ? Math.round(scrollHeight - contentBottom - padding) : 0,
      scrollHeight,
      clientHeight,
      contentBottom: Math.round(contentBottom),
      padding,
      deepest:
        deepestBottom > contentBottom + 1 ? `${deepest} (bottom ${Math.round(deepestBottom)})` : '',
      documentExcess: Math.max(0, doc.scrollHeight - window.innerHeight),
    }
  })
}

/** Not pages: they only finish a flow, then leave (as in 31-page-rhythm). */
const NOT_PAGES: Record<string, string> = {
  '/settings/tenant/create': 'creates an organization, then leaves',
  '/ci-cd/github-app/callback': 'finishes the GitHub App install, then leaves',
}

const VIEWPORTS = [
  { width: 1440, height: 900 },
  { width: 390, height: 844 },
] as const

for (const route of staticRoutes()) {
  if (NOT_PAGES[route]) continue
  test(`scroll ends after the last content on ${route}`, { tag: ['@shell'] }, async ({ page }) => {
    test.skip(!(await open(page, route)), `${route} redirects`)
    await expect(page.locator('main h1').first()).toBeVisible({ timeout: 30_000 })
    for (const vp of VIEWPORTS) {
      await page.setViewportSize(vp)
      // Let charts and observers settle at the new width.
      await page.waitForTimeout(400)
      await page.evaluate(() => {
        const main = document.querySelector('main#content')!
        main.scrollTo(0, main.scrollHeight)
      })
      await page.waitForTimeout(200)
      const m = await measureScrollEnd(page)
      const at = `${route} at ${vp.width}px`
      expect
        .soft(
          m.excess,
          `${at}: scrolls ${m.excess}px past its last content (scroll height ${m.scrollHeight}, content ends at ${m.contentBottom}, padding ${m.padding}; deepest box ${m.deepest || 'content'})`
        )
        .toBeLessThanOrEqual(SLACK_PX)
      expect.soft(m.documentExcess, `${at}: the document itself scrolls`).toBe(0)
    }
  })
}
