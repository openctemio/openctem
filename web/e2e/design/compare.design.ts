import { readFileSync } from 'node:fs'
import path from 'node:path'

import { expect, test } from '@playwright/test'
import sharp from 'sharp'

import { compareImages } from './compare'
import { DEFAULT_THRESHOLD } from './manifest'

/**
 * The comparator's own contract, on a committed reference image: what the
 * default threshold forgives (the same image, a one-pixel shift) and what it
 * catches (a recoloured button, a missing block, a size change).
 */

const REF = readFileSync(path.join(__dirname, 'references', 'sign-in', '1440-light.png'))
const opts = { pixel: DEFAULT_THRESHOLD.pixel }

async function size(png: Buffer) {
  const m = await sharp(png).metadata()
  return { width: m.width!, height: m.height! }
}

test('the same image does not differ', async () => {
  const r = await compareImages(REF, REF, opts)
  expect(r.diffPixels).toBe(0)
})

test('a one-pixel shift stays under the default ratio', async () => {
  const { width, height } = await size(REF)
  const shifted = await sharp(REF)
    .extend({ left: 1, top: 1, background: '#ffffff' })
    .extract({ left: 0, top: 0, width, height })
    .png()
    .toBuffer()
  const r = await compareImages(REF, shifted, opts)
  expect(r.ratio).toBeLessThanOrEqual(DEFAULT_THRESHOLD.ratio)
})

test('a recoloured 380 x 36 button exceeds the default ratio', async () => {
  const button = await sharp({
    create: { width: 380, height: 36, channels: 4, background: '#0a1628' },
  })
    .png()
    .toBuffer()
  const changed = await sharp(REF)
    .composite([{ input: button, left: 25, top: 299 }])
    .png()
    .toBuffer()
  const r = await compareImages(REF, changed, opts)
  expect(r.ratio).toBeGreaterThan(DEFAULT_THRESHOLD.ratio)
})

test('a declared difference is left out of the comparison', async () => {
  const block = await sharp({
    create: { width: 380, height: 36, channels: 4, background: '#0a1628' },
  })
    .png()
    .toBuffer()
  const changed = await sharp(REF)
    .composite([{ input: block, left: 25, top: 299 }])
    .png()
    .toBuffer()
  const r = await compareImages(REF, changed, {
    ...opts,
    masks: [{ x: 25, y: 299, width: 380, height: 36 }],
  })
  expect(r.diffPixels).toBe(0)
})

test('a taller page counts its extra area as different', async () => {
  const { height } = await size(REF)
  const taller = await sharp(REF)
    .extend({ bottom: Math.round(height * 0.1), background: '#ffffff' })
    .png()
    .toBuffer()
  const r = await compareImages(REF, taller, opts)
  expect(r.ratio).toBeGreaterThan(0.05)
})
