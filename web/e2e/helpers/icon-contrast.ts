import type { Page } from '@playwright/test'

/** An icon-only control's visible icon: size, colours at rest and contrast. */
export type IconContrast = {
  name: string
  /** Rendered icon width in px. */
  size: number
  /** The icon colour after opacity, composited on its background (rgb). */
  icon: string
  /** The opaque colour behind the control at rest (rgb). */
  background: string
  /** WCAG contrast ratio, two decimals. */
  ratio: number
}

/**
 * Measures, for each visible control matched by `selector`, the contrast of
 * its visible icon against the background behind it at rest: the computed
 * icon colour times the opacity of the icon and its ancestors, over the
 * translucent backgrounds of the control and its ancestors down to the first
 * opaque one. Colours are resolved by the browser (a canvas reads any CSS
 * colour, color-mix and oklab included), so the result is what is on screen.
 * Move the mouse away first: a hover background is not "at rest".
 */
export async function iconContrast(page: Page, selector: string): Promise<IconContrast[]> {
  return page.evaluate((sel) => {
    const ctx = document.createElement('canvas').getContext('2d', { willReadFrequently: true })!
    type C = [number, number, number, number]
    const rgba = (css: string): C => {
      ctx.clearRect(0, 0, 1, 1)
      ctx.fillStyle = '#000'
      ctx.fillStyle = css
      ctx.fillRect(0, 0, 1, 1)
      const d = ctx.getImageData(0, 0, 1, 1).data
      return [d[0], d[1], d[2], d[3] / 255]
    }
    const over = (top: C, under: C): C => {
      const a = top[3]
      return [0, 1, 2].map((i) => top[i] * a + under[i] * (1 - a)).concat(1) as C
    }
    const lum = (c: C) => {
      const ch = (v: number) => {
        const s = v / 255
        return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
      }
      return 0.2126 * ch(c[0]) + 0.7152 * ch(c[1]) + 0.0722 * ch(c[2])
    }
    const visible = (e: Element) => {
      const b = e.getBoundingClientRect()
      const s = getComputedStyle(e)
      return b.width > 0 && b.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'
    }
    const hex = (c: C) => `rgb(${c.slice(0, 3).map(Math.round).join(', ')})`
    const out: {
      name: string
      size: number
      icon: string
      background: string
      ratio: number
    }[] = []
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(sel))) {
      if (!visible(el)) continue
      const opacityOf = (e: Element) => {
        let o = 1
        for (let n: Element | null = e; n; n = n.parentElement)
          o *= Number(getComputedStyle(n).opacity)
        return o
      }
      // The first icon on screen (a row's hover-only actions sit at opacity 0).
      const svg = Array.from(el.querySelectorAll('svg')).find((s) => visible(s) && opacityOf(s) > 0)
      if (!svg) continue
      // Backgrounds from the control up to the first opaque one.
      const layers: C[] = []
      for (let n: Element | null = el; n; n = n.parentElement) {
        const c = rgba(getComputedStyle(n).backgroundColor)
        if (c[3] > 0) layers.push(c)
        if (c[3] >= 1) break
      }
      let bg: C = [255, 255, 255, 1]
      for (const l of layers.reverse()) bg = over(l, bg)
      const opacity = opacityOf(svg)
      const raw = rgba(getComputedStyle(svg).color)
      const icon = over([raw[0], raw[1], raw[2], raw[3] * opacity], bg)
      const [hi, lo] = [lum(icon), lum(bg)].sort((a, b) => b - a)
      out.push({
        name:
          el.getAttribute('aria-label') ??
          el.querySelector('.sr-only')?.textContent?.trim() ??
          el.textContent?.trim() ??
          '',
        size: Math.round(svg.getBoundingClientRect().width),
        icon: hex(icon),
        background: hex(bg),
        ratio: Math.round(((hi + 0.05) / (lo + 0.05)) * 100) / 100,
      })
    }
    return out
  }, selector)
}

/** The owner's floor for icon-only shell controls (WCAG asks 3:1 for non-text). */
export const ICON_CONTRAST_FLOOR = 4.5
