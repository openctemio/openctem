import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'

import { expect, test } from '@playwright/test'

import { compareImages, type Rect } from './compare'
import { MANIFEST } from './manifest'
import { preparePage, settle, unmockedRoutes, useFixtureSet } from './prepare'

/**
 * Reference pass: each manifest page at each width and theme, compared with the
 * image exported from its design board. Expected, actual and diff are attached
 * to the test (and land in the job's artifact); a line per comparison goes to
 * summary.md for the job summary.
 */

const REFERENCES = path.join(__dirname, 'references')

/** One table row per comparison in test-results-design/summary.md (global-setup.ts writes the header). */
function summary(projectOutputDir: string, line: string): void {
  appendFileSync(path.join(projectOutputDir, '..', 'summary.md'), `${line}\n`)
}

for (const entry of MANIFEST) {
  for (const width of entry.widths) {
    for (const theme of entry.themes) {
      const name = `${width}-${theme}`
      test(`${entry.id} ${name} matches ${entry.board.file}`, async ({ page, baseURL }, info) => {
        const refPath = path.join(REFERENCES, entry.id, `${name}.png`)
        const pending = entry.expected === 'pending'
        if (!existsSync(refPath)) {
          summary(
            info.project.outputDir,
            `| ${entry.id} | ${name} | no reference | ${entry.expected} |`
          )
          expect(pending, `missing reference ${refPath}: run scripts/design-reference.mjs`).toBe(
            true
          )
          return
        }

        await useFixtureSet(entry.fixtures)
        await preparePage(page, { baseURL: baseURL!, theme, locale: 'en', width })
        await page.goto(entry.route)
        await settle(page, entry.page.ready)

        const crop = page.locator(entry.page.crop).first()
        const box = await crop.boundingBox()
        if (!box) throw new Error(`${entry.page.crop} has no box on ${entry.route}`)
        const masks: Rect[] = []
        for (const d of entry.differences ?? []) {
          for (const el of await page.locator(d.selector).all()) {
            const b = await el.boundingBox()
            if (b) masks.push({ x: b.x - box.x, y: b.y - box.y, width: b.width, height: b.height })
          }
        }
        const actual = await crop.screenshot({
          animations: 'disabled',
          caret: 'hide',
          scale: 'css',
        })
        const expected = readFileSync(refPath)
        const result = await compareImages(expected, actual, {
          pixel: entry.threshold.pixel,
          masks,
        })

        // Files in the test's output folder (the job uploads the folder) and attachments in the report.
        for (const [label, body] of [
          ['expected', expected],
          ['actual', actual],
          ['diff', result.diffPng],
        ] as const) {
          const file = info.outputPath(`${label}.png`)
          writeFileSync(file, body)
          await info.attach(label, { path: file, contentType: 'image/png' })
        }

        const pct = (result.ratio * 100).toFixed(2)
        const sizes = `${result.expectedSize.width}x${result.expectedSize.height} vs ${result.actualSize.width}x${result.actualSize.height}`
        const verdict = result.ratio <= entry.threshold.ratio ? 'match' : 'differs'
        summary(
          info.project.outputDir,
          `| ${entry.id} | ${name} | ${pct}% (limit ${(entry.threshold.ratio * 100).toFixed(2)}%), ${sizes} | ${entry.expected}: ${verdict} |`
        )
        info.annotations.push({
          type: pending ? 'design-pending' : 'design-match',
          description: `${pct}% of pixels differ (${sizes})`,
        })

        const misses = await unmockedRoutes()
        if (pending) return
        expect(misses, 'routes the page called that no fixture answers').toEqual([])
        expect(
          result.ratio,
          `${entry.id} ${name}: ${pct}% of pixels differ from ${entry.board.file} (${sizes}); see the diff attachment`
        ).toBeLessThanOrEqual(entry.threshold.ratio)
      })
    }
  }
}
