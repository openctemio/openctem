import sharp from 'sharp'

/**
 * Perceptual comparison of a reference image (rendered from a design board)
 * with a screenshot of the real page.
 *
 * A pixel differs when its colour distance in YIQ space (the luma-weighted
 * distance used for screenshot diffs: brightness counts about twice as much as
 * hue) is above `pixel` (0..1, share of the largest possible distance) and no
 * pixel within one pixel of it in the other image is within that distance.
 * The second rule forgives anti-aliasing and a sub-pixel text shift, which two
 * renderings of the same design always have, while a moved, missing, recoloured
 * or resized element still counts in full.
 *
 * Images of different sizes are compared on the larger canvas; the area only
 * one image covers counts as different, so a page that is taller than the
 * board fails by that share.
 */

export interface Rect {
  x: number
  y: number
  width: number
  height: number
}

export interface CompareOptions {
  /** Per-pixel colour distance threshold, 0..1. */
  pixel: number
  /** Areas left out of the comparison in both images (declared differences). */
  masks?: Rect[]
}

export interface CompareResult {
  /** Differing pixels / pixels of the larger canvas. */
  ratio: number
  diffPixels: number
  width: number
  height: number
  expectedSize: { width: number; height: number }
  actualSize: { width: number; height: number }
  /** PNG: the reference faded to grey with differing pixels in red. */
  diffPng: Buffer
}

interface Raw {
  data: Buffer
  width: number
  height: number
}

const MAX_YIQ_DELTA = 35215

async function decode(png: Buffer): Promise<Raw> {
  const { data, info } = await sharp(png)
    .flatten({ background: '#ffffff' })
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true })
  return { data, width: info.width, height: info.height }
}

/** Places `img` on a `width` x `height` canvas; uncovered pixels are transparent (alpha 0). */
function onCanvas(img: Raw, width: number, height: number): Buffer {
  if (img.width === width && img.height === height) return img.data
  const out = Buffer.alloc(width * height * 4)
  for (let y = 0; y < img.height; y++) {
    img.data.copy(out, y * width * 4, y * img.width * 4, (y + 1) * img.width * 4)
  }
  return out
}

function yiqDelta(a: Buffer, i: number, b: Buffer, j: number): number {
  if (a[i + 3] === 0 || b[j + 3] === 0) return a[i + 3] === b[j + 3] ? 0 : MAX_YIQ_DELTA
  const dr = a[i] - b[j]
  const dg = a[i + 1] - b[j + 1]
  const db = a[i + 2] - b[j + 2]
  const y = dr * 0.29889531 + dg * 0.58662247 + db * 0.11448223
  const iq = dr * 0.59597799 - dg * 0.2741761 - db * 0.32180189
  const q = dr * 0.21147017 - dg * 0.52261711 + db * 0.31114694
  return 0.5053 * y * y + 0.299 * iq * iq + 0.1957 * q * q
}

/** True when some pixel of `other` within one pixel of (x, y) matches `src` at (x, y). */
function nearMatch(
  src: Buffer,
  other: Buffer,
  x: number,
  y: number,
  width: number,
  height: number,
  limit: number
): boolean {
  const i = (y * width + x) * 4
  for (let dy = -1; dy <= 1; dy++) {
    const yy = y + dy
    if (yy < 0 || yy >= height) continue
    for (let dx = -1; dx <= 1; dx++) {
      const xx = x + dx
      if (xx < 0 || xx >= width) continue
      if (yiqDelta(src, i, other, (yy * width + xx) * 4) <= limit) return true
    }
  }
  return false
}

function paint(buf: Buffer, width: number, height: number, r: Rect): void {
  const x0 = Math.max(0, Math.floor(r.x))
  const y0 = Math.max(0, Math.floor(r.y))
  const x1 = Math.min(width, Math.ceil(r.x + r.width))
  const y1 = Math.min(height, Math.ceil(r.y + r.height))
  for (let y = y0; y < y1; y++) {
    for (let x = x0; x < x1; x++) {
      const i = (y * width + x) * 4
      buf[i] = 255
      buf[i + 1] = 0
      buf[i + 2] = 255
      buf[i + 3] = 255
    }
  }
}

export async function compareImages(
  expectedPng: Buffer,
  actualPng: Buffer,
  opts: CompareOptions
): Promise<CompareResult> {
  const [e, a] = await Promise.all([decode(expectedPng), decode(actualPng)])
  const width = Math.max(e.width, a.width)
  const height = Math.max(e.height, a.height)
  const exp = Buffer.from(onCanvas(e, width, height))
  const act = Buffer.from(onCanvas(a, width, height))
  for (const m of opts.masks ?? []) {
    paint(exp, width, height, m)
    paint(act, width, height, m)
  }

  const limit = MAX_YIQ_DELTA * opts.pixel * opts.pixel
  const diff = Buffer.alloc(width * height * 4)
  let diffPixels = 0
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 4
      const differs =
        yiqDelta(exp, i, act, i) > limit &&
        !(
          nearMatch(exp, act, x, y, width, height, limit) &&
          nearMatch(act, exp, x, y, width, height, limit)
        )
      if (differs) {
        diffPixels++
        diff[i] = 230
        diff[i + 1] = 0
        diff[i + 2] = 40
      } else {
        // The reference, as a faint grey, so the red reads against it.
        const g = exp[i + 3] === 0 ? 255 : 255 - Math.round((255 - exp[i + 1]) * 0.15)
        diff[i] = g
        diff[i + 1] = g
        diff[i + 2] = g
      }
      diff[i + 3] = 255
    }
  }

  const diffPng = await sharp(diff, { raw: { width, height, channels: 4 } })
    .png({ compressionLevel: 9 })
    .toBuffer()
  return {
    ratio: width * height === 0 ? 0 : diffPixels / (width * height),
    diffPixels,
    width,
    height,
    expectedSize: { width: e.width, height: e.height },
    actualSize: { width: a.width, height: a.height },
    diffPng,
  }
}
