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

// The root layout preloads the Inter files of the first paint, per language,
// so they arrive with the stylesheet (src/lib/first-paint-fonts.ts). Next.js
// sends them as an HTTP Link header (or as <link> tags in the head).
for (const [locale, files] of [
  ['en', ['inter-latin-wght-normal.woff2']],
  [
    'vi',
    [
      'inter-latin-wght-normal.woff2',
      'inter-latin-ext-wght-normal.woff2',
      'inter-vietnamese-wght-normal.woff2',
    ],
  ],
] as const) {
  test(`preloads the first-paint fonts in ${locale}`, async ({ request }) => {
    const res = await request.get('/login', { headers: { cookie: `locale=${locale}` } })
    const header = (res.headers()['link'] ?? '').split(/,\s*(?=<)/)
    const tags = [...(await res.text()).matchAll(/<link[^>]*rel="preload"[^>]*>/g)].map((m) => m[0])
    const fonts = [...header, ...tags].filter((l) => /as="?font"?/.test(l))
    for (const f of files) {
      expect(fonts.some((l) => l.includes(`/fonts/${f}`) && /crossorigin/i.test(l))).toBe(true)
    }
    expect(fonts).toHaveLength(files.length)
  })
}
