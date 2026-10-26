import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Key pages at 1440 light and dark and 390 light. Masked: what changes from
 * run to run with the same seed (relative times, timestamps, live counts in
 * the shell). A change beyond 2% of the pixels fails with a diff image.
 */

const PAGES: { name: string; path: string; ready: (p: Page) => Promise<void> }[] = [
  { name: 'dashboard', path: '/', ready: (p) => expect(p.getByRole('main')).toBeVisible() },
  {
    name: 'findings',
    path: '/findings',
    ready: (p) => expect(p.getByRole('heading', { level: 1 })).toBeVisible(),
  },
  {
    name: 'assets',
    path: '/assets',
    ready: (p) => expect(p.getByRole('heading', { level: 1 })).toBeVisible(),
  },
  {
    name: 'scans',
    path: '/scans',
    ready: (p) => expect(p.getByRole('heading', { level: 1 })).toBeVisible(),
  },
  {
    name: 'remediation-tasks',
    path: '/remediation/tasks',
    ready: (p) => expect(p.getByRole('heading', { level: 1 })).toBeVisible(),
  },
  {
    name: 'my-work',
    path: '/my-work',
    ready: (p) => expect(p.getByRole('heading', { level: 1 })).toBeVisible(),
  },
  {
    name: 'settings',
    path: '/settings',
    ready: (p) => expect(p.getByRole('heading', { level: 1 })).toBeVisible(),
  },
]

const VARIANTS = [
  { label: '1440-light', width: 1440, height: 900, scheme: 'light' as const },
  { label: '1440-dark', width: 1440, height: 900, scheme: 'dark' as const },
  { label: '390-light', width: 390, height: 844, scheme: 'light' as const },
]

// Values that differ between two runs of the same seed.
const VOLATILE =
  'time, [data-slot="relative-time"], [data-volatile], [data-slot="nav-count"], [data-slot="header-approvals"] span'

for (const v of VARIANTS) {
  for (const pg of PAGES) {
    test(`${pg.name} ${v.label}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: v.scheme, reducedMotion: 'reduce' })
      await page.addInitScript((scheme) => {
        try {
          window.localStorage.setItem('theme', scheme)
        } catch {
          // storage blocked: the emulated scheme still applies
        }
      }, v.scheme)
      await page.setViewportSize({ width: v.width, height: v.height })
      await page.goto(pg.path)
      await pg.ready(page)
      await page.waitForLoadState('networkidle')
      await expect(page).toHaveScreenshot(`${pg.name}-${v.label}.png`, {
        fullPage: false,
        mask: [page.locator(VOLATILE)],
      })
    })
  }
}
