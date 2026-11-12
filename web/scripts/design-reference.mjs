#!/usr/bin/env node
/**
 * Exports the reference images of the design gate from a design board
 * (docs/development/design-gate.md).
 *
 *   node scripts/design-reference.mjs --board <dir>/P3-Login.dc.html --runtime <dir>/support.js [--id sign-in]
 *
 * For every manifest entry whose board is that file (or the entry --id names),
 * it renders the board in Chromium at each width and theme of the entry, crops
 * the entry's `board.crop` element and writes
 * e2e/design/references/<id>/<width>-<theme>.png. It then writes the board
 * file's SHA-256 into the entry in e2e/design/manifest.ts, so a reference
 * update shows in review as a changed image plus a changed board hash.
 *
 * The board's own font links are answered with the web app's self-hosted font
 * files (public/fonts), so board and page draw text with the same files, and
 * every other outside request is refused: the export needs no network.
 * `--runtime` is the board runtime the board loads as ./support.js; boards and
 * runtime stay outside the repository.
 */

import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'

import { chromium } from '@playwright/test'
import sharp from 'sharp'

import { MANIFEST } from '../e2e/design/manifest.ts'

const WEB = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const MANIFEST_FILE = path.join(WEB, 'e2e/design/manifest.ts')
const REFERENCES = path.join(WEB, 'e2e/design/references')
const FONTS = path.join(WEB, 'public/fonts')
const HEIGHT = { 1440: 900, 390: 844 }

const FREEZE_CSS = `*,*::before,*::after{transition:none!important;animation:none!important;caret-color:transparent!important}html{scrollbar-width:none}`

// One family per file set; unicode-range keeps the browser's choice per script.
const fontCss = (origin) =>
  [
    ['Inter', 'inter', '100 900'],
    ['JetBrains Mono', 'jetbrains-mono', '100 800'],
  ]
    .flatMap(([family, prefix, weight]) =>
      [
        [
          'latin',
          'U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD',
        ],
        [
          'latin-ext',
          'U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF',
        ],
        [
          'vietnamese',
          'U+0102-0103,U+0110-0111,U+0128-0129,U+0168-0169,U+01A0-01A1,U+01AF-01B0,U+0300-0301,U+0303-0304,U+0308-0309,U+0323,U+0329,U+1EA0-1EF9,U+20AB',
        ],
      ].map(
        ([subset, range]) =>
          `@font-face{font-family:'${family}';font-style:normal;font-weight:${weight};font-display:block;src:url(${origin}/fonts/${prefix}-${subset}-wght-normal.woff2) format('woff2');unicode-range:${range}}`
      )
    )
    .join('\n')

function fail(msg) {
  console.error(`design-reference: ${msg}`)
  process.exit(1)
}

const { values } = parseArgs({
  options: { board: { type: 'string' }, runtime: { type: 'string' }, id: { type: 'string' } },
})
if (!values.board || !values.runtime) {
  fail(
    'usage: --board <path to .dc.html> --runtime <path to the board runtime (support.js)> [--id <entry>]'
  )
}
const boardFile = path.resolve(values.board)
const runtimeFile = path.resolve(values.runtime)
const boardName = path.basename(boardFile)
const entries = MANIFEST.filter((e) =>
  values.id ? e.id === values.id : e.board.file === boardName
)
if (entries.length === 0) fail(`no manifest entry uses ${values.id ?? boardName}`)
for (const e of entries) {
  if (e.board.file !== boardName) fail(`entry ${e.id} uses ${e.board.file}, not ${boardName}`)
}

const boardBytes = readFileSync(boardFile)
const sha256 = createHash('sha256').update(boardBytes).digest('hex')

// The board, its runtime and the fonts, on 127.0.0.1 only.
const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const send = (type, body) => {
    res.writeHead(200, { 'content-type': type })
    res.end(body)
  }
  if (url.pathname === '/board.html') return send('text/html; charset=utf-8', boardBytes)
  if (url.pathname === '/support.js') return send('text/javascript', readFileSync(runtimeFile))
  const font = /^\/fonts\/([a-z0-9-]+\.woff2)$/.exec(url.pathname)
  if (font) {
    try {
      return send('font/woff2', readFileSync(path.join(FONTS, font[1])))
    } catch {
      // fall through to 404
    }
  }
  res.writeHead(404)
  res.end()
})
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`

const browser = await chromium.launch()
try {
  for (const entry of entries) {
    const dir = path.join(REFERENCES, entry.id)
    mkdirSync(dir, { recursive: true })
    for (const width of entry.widths) {
      for (const theme of entry.themes) {
        const context = await browser.newContext({
          viewport: { width, height: HEIGHT[width] ?? 900 },
          deviceScaleFactor: 1,
          locale: 'en-US',
          timezoneId: 'UTC',
          reducedMotion: 'reduce',
        })
        const page = await context.newPage()
        await page.route('**/*', (route) => {
          const u = new URL(route.request().url())
          if (u.origin === origin) return route.continue()
          if (u.hostname === 'fonts.googleapis.com') {
            return route.fulfill({ contentType: 'text/css', body: fontCss(origin) })
          }
          return route.abort()
        })
        await page.goto(`${origin}/board.html`)
        await page.waitForSelector('#dc-root .r', { timeout: 30_000 })
        if (theme === 'dark') {
          await page.evaluate(() => window.__dcSetProps(window.__dcRootName(), { dark: true }))
          await page.waitForSelector('#dc-root .r[data-theme="dark"]')
        }
        await page.addStyleTag({ content: FREEZE_CSS })
        await page.evaluate(() => document.fonts.ready.then(() => undefined))
        const crop = page.locator(entry.board.crop).first()
        if ((await crop.count()) === 0) fail(`${entry.board.crop} not found in ${boardName}`)
        const shot = await crop.screenshot({ animations: 'disabled', caret: 'hide', scale: 'css' })
        const png = await sharp(shot).png({ compressionLevel: 9, effort: 10 }).toBuffer()
        const out = path.join(dir, `${width}-${theme}.png`)
        writeFileSync(out, png)
        const meta = await sharp(png).metadata()
        console.log(
          `${path.relative(WEB, out)}  ${meta.width}x${meta.height}  ${(png.length / 1024).toFixed(1)} KiB`
        )
        await context.close()
      }
    }
  }
} finally {
  await browser.close()
  server.close()
}

// Record the board hash in each exported entry.
let manifest = readFileSync(MANIFEST_FILE, 'utf8')
for (const entry of entries) {
  const at = manifest.indexOf(`id: '${entry.id}'`)
  const hashAt = manifest.indexOf('sha256: ', at)
  if (at < 0 || hashAt < 0) fail(`cannot find the sha256 of ${entry.id} in manifest.ts`)
  const lineEnd = manifest.indexOf('\n', hashAt)
  manifest = `${manifest.slice(0, hashAt)}sha256: '${sha256}',${manifest.slice(lineEnd)}`
}
writeFileSync(MANIFEST_FILE, manifest)
console.log(`${boardName} sha256 ${sha256} recorded for ${entries.map((e) => e.id).join(', ')}`)
