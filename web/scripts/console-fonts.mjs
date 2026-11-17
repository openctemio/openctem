#!/usr/bin/env node
// console-fonts.mjs: runs before `dev:console` and `build:console`.
//
// The shared stylesheet (src/styles/fonts.css) loads the self-hosted fonts from
// /fonts/*.woff2. Next.js serves static files from the app's own public/
// folder, and the console (web/console) has none: `next dev console` and
// `next start console` (the console's e2e suite and local runs) answered 404
// for every font and drew the pages in a fallback font. This copies the font
// files from public/fonts to console/public/fonts (ignored by git), so every
// way of running the console draws the same text as the console image, which
// copies the same files in the Dockerfile.
import { copyFileSync, mkdirSync, readdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const from = resolve(web, 'public/fonts')
const to = resolve(web, 'console/public/fonts')

const fonts = readdirSync(from).filter((f) => f.endsWith('.woff2'))
if (fonts.length === 0) {
  console.error(`console-fonts: no .woff2 file in ${from}`)
  process.exit(1)
}
mkdirSync(to, { recursive: true })
for (const f of fonts) copyFileSync(resolve(from, f), resolve(to, f))
