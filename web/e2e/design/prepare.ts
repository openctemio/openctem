import type { Page } from '@playwright/test'

import type { FixtureSet } from './fixtures/api'
import { TODAY } from './fixtures/sample-data'
import type { Theme } from './manifest'

/** Where the gate's mock API listens (playwright.design.config.ts starts it). */
export const MOCK_API_URL = `http://127.0.0.1:${process.env.DESIGN_MOCK_PORT ?? '3199'}`

export const HEIGHT: Record<number, number> = { 1440: 900, 390: 844 }

/** Freezes what changes between two runs: transitions, animations, the caret, the scrollbar. */
const FREEZE_CSS = `
*, *::before, *::after {
  transition: none !important;
  animation: none !important;
  caret-color: transparent !important;
}
html { scrollbar-width: none; }
nextjs-portal { display: none !important; }
`

export async function useFixtureSet(set: FixtureSet): Promise<void> {
  const res = await fetch(`${MOCK_API_URL}/__design/fixture?set=${set}`, { method: 'POST' })
  if (!res.ok) throw new Error(`mock API refused fixture set ${set}: ${res.status}`)
}

/** Backend routes the page called that no fixture answers. */
export async function unmockedRoutes(): Promise<string[]> {
  const res = await fetch(`${MOCK_API_URL}/__design/misses`)
  return ((await res.json()) as { misses: string[] }).misses
}

/**
 * Sets up a page like every board: the fixed date, the theme, the locale, no
 * network beyond the web server (fonts are self-hosted), no motion.
 */
export async function preparePage(
  page: Page,
  opts: { baseURL: string; theme: Theme; locale: 'en' | 'vi'; width: number }
): Promise<void> {
  const origin = new URL(opts.baseURL).origin
  await page.route('**/*', (route) =>
    new URL(route.request().url()).origin === origin ? route.continue() : route.abort()
  )
  await page.clock.setFixedTime(new Date(TODAY))
  await page.setViewportSize({ width: opts.width, height: HEIGHT[opts.width] ?? 900 })
  await page.emulateMedia({ colorScheme: opts.theme, reducedMotion: 'reduce' })
  await page.context().addCookies([{ name: 'locale', value: opts.locale, url: origin }])
  await page.addInitScript((theme) => {
    try {
      window.localStorage.setItem('theme', theme)
    } catch {
      // storage blocked: the emulated colour scheme still applies
    }
  }, opts.theme)
}

/** After navigation: frozen styles in, fonts loaded, nothing in flight. */
export async function settle(page: Page, ready: string): Promise<void> {
  await page.locator(ready).first().waitFor({ state: 'visible' })
  await page.addStyleTag({ content: FREEZE_CSS })
  await page.waitForLoadState('networkidle')
  await page.evaluate(() => document.fonts.ready.then(() => undefined))
}
