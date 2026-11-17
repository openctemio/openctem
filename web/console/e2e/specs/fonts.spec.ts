import { readFileSync } from 'node:fs'
import path from 'node:path'
import { test, expect } from '@playwright/test'

/**
 * The console serves the self-hosted fonts that the shared stylesheet loads
 * (src/styles/fonts.css). The console app has no public/ folder of its own:
 * scripts/console-fonts.mjs copies the files before `dev:console` and
 * `build:console`, and the console image copies them in the Dockerfile.
 * Without them every page fell back to a system font.
 */
const css = readFileSync(path.resolve(__dirname, '../../../src/styles/fonts.css'), 'utf8')
const urls = [...css.matchAll(/url\('(\/fonts\/[^']+\.woff2)'\)/g)].map((m) => m[1])

test('the stylesheet names the font files', () => {
  expect(urls.length).toBeGreaterThan(0)
})

for (const url of urls) {
  test(`serves ${url}`, async ({ request }) => {
    const res = await request.get(url)
    expect(res.status()).toBe(200)
    expect(res.headers()['content-type']).toContain('font/woff2')
  })
}
