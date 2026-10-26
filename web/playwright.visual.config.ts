import { defineConfig } from '@playwright/test'
import base from './playwright.config'

/**
 * Visual regression of the key pages (research/236 F6): screenshots at
 * desktop and phone width, light and dark, compared with the baselines in
 * e2e/visual/__screenshots__ within a small tolerance. Not part of the e2e
 * suite: it runs on the `run-visual` label, nightly and on demand
 * (.github/workflows/web-visual.yml), so pull request CI stays fast.
 *
 *   npx playwright test -c playwright.visual.config.ts                 compare
 *   npx playwright test -c playwright.visual.config.ts --update-snapshots   new baselines
 *
 * Baselines are taken in CI (the fonts are self-hosted, so the CI images
 * render the same every run); the workflow's update mode uploads them as an
 * artifact to commit.
 */
export default defineConfig({
  ...base,
  testMatch: '**/*.visual.ts',
  snapshotPathTemplate: '{testDir}/visual/__screenshots__/{arg}{ext}',
  retries: 0,
  expect: {
    ...base.expect,
    toHaveScreenshot: {
      // Seeded data, fonts and layout are stable; counts and dates are masked.
      maxDiffPixelRatio: 0.02,
      animations: 'disabled',
      caret: 'hide',
      scale: 'css',
    },
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
})
