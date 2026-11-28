import type { Page } from '@playwright/test'
import { expect } from '@playwright/test'

/**
 * The scroll ends where the page ends.
 *
 * A page that can scroll stops a normal bottom padding after its last visible
 * content: the page scroller's (`main#content`) scrollable height may exceed
 * the bottom of the last visible element by at most the page's own bottom
 * padding plus 8px, and the document itself never scrolls (the shell's page
 * scroller is the one scroller). Visible content is text, media, controls and
 * painted boxes; content inside a box that clips it (overflow, `sr-only`)
 * counts only as far as the clip shows it.
 *
 * It caught a box nobody sees keeping the scroll going: Program health's
 * screen-reader table (`sr-only` does not shrink a table) added a screen or
 * more of empty background below the last card, and a list's out-of-flow
 * last part (its screen-reader status line, or on a phone the hidden desktop
 * table) kept the list's spacing under a table without a pager.
 */

const SLACK_PX = 8

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
    // The shell's notices come first in the scroller and are not the page.
    const first = Array.from(main.children).find(
      (c) => (c as HTMLElement).dataset?.slot !== 'shell-banners'
    ) as HTMLElement | undefined
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

/** Scrolls the page to its end, checks where the scroll stops, and scrolls back to the top. */
export async function checkScrollEnd(page: Page, at: string) {
  await page.evaluate(() => {
    const main = document.querySelector('main#content')
    main?.scrollTo(0, main.scrollHeight)
  })
  await page.waitForTimeout(150)
  const m = await measureScrollEnd(page)
  await page.evaluate(() => document.querySelector('main#content')?.scrollTo(0, 0))
  expect
    .soft(
      m.excess,
      `${at}: scrolls ${m.excess}px past its last content (scroll height ${m.scrollHeight}, content ends at ${m.contentBottom}, padding ${m.padding}; deepest box ${m.deepest || 'content'})`
    )
    .toBeLessThanOrEqual(SLACK_PX)
  expect.soft(m.documentExcess, `${at}: the document itself scrolls`).toBe(0)
}
