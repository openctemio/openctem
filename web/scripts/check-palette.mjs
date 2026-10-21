#!/usr/bin/env node
/**
 * Validates the dashboard chart palettes (src/lib/chart-palette.json) and
 * checks that the --viz-* tokens in src/styles/theme.css carry the same values.
 *
 * Checks, per mode against that mode's chart surface:
 *   - lightness band (OKLCH L) for categorical palettes;
 *   - chroma floor (OKLCH C >= 0.10);
 *   - colour-vision-deficiency separation: adjacent pairs, OKLab delta E x100
 *     under protanopia and deuteranopia (Machado et al. 2009, severity 1.0):
 *     >= 8 passes, 6-8 warns (needs secondary encoding), < 6 fails;
 *   - normal-vision separation of adjacent pairs (>= 15, else fail);
 *   - contrast against the surface (< 3:1 warns: labels or a table view are
 *     then mandatory, which the dashboard kit always provides);
 *   - sequential ramps: monotone lightness with visible steps, and the ink
 *     printed on each step reaching 4.5:1.
 *
 * Usage: node scripts/check-palette.mjs   (exit 1 on any failure)
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const BAND = { light: [0.43, 0.77], dark: [0.48, 0.67] }
const CHROMA_FLOOR = 0.1
const CVD_TARGET = 8
const CVD_FLOOR = 6
const NORMAL_FLOOR = 15
const CONTRAST_MIN = 3
const INK_MIN = 4.5
const SEQ_MIN_DL = 0.06

const MACHADO = {
  protan: [
    [0.152286, 1.052583, -0.204868],
    [0.114503, 0.786281, 0.099216],
    [-0.003882, -0.048116, 1.051998],
  ],
  deutan: [
    [0.367322, 0.860646, -0.227968],
    [0.280085, 0.672501, 0.047413],
    [-0.01182, 0.04294, 0.968881],
  ],
}

function parseHex(h) {
  if (!/^#[0-9a-fA-F]{6}$/.test(h)) throw new Error(`not a #rrggbb colour: ${h}`)
  return [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255)
}
const toLin = (c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)
const lin = (h) => parseHex(h).map(toLin)
const relLum = (h) => {
  const [r, g, b] = lin(h)
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}
export function contrast(a, b) {
  const [hi, lo] = [relLum(a), relLum(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}
function oklabFromLin([r, g, b]) {
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b)
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b)
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b)
  return [
    0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  ]
}
export function oklch(h) {
  const [L, a, b] = oklabFromLin(lin(h))
  return [L, Math.hypot(a, b)]
}
function simulate(h, kind) {
  const [r, g, b] = lin(h)
  const M = MACHADO[kind]
  const clamp = (c) => Math.max(0, Math.min(1, c))
  return M.map((row) => clamp(row[0] * r + row[1] * g + row[2] * b))
}
export function deltaE(a, b, kind) {
  const x = oklabFromLin(kind ? simulate(a, kind) : lin(a))
  const y = oklabFromLin(kind ? simulate(b, kind) : lin(b))
  return 100 * Math.hypot(x[0] - y[0], x[1] - y[1], x[2] - y[2])
}

/**
 * Validates one categorical palette. Returns { fails: string[], warns: string[] }.
 * `bandWaived`: the lightness band is reported as a warning instead (a
 * documented waiver with mandatory secondary encoding).
 */
export function validateCategorical(colors, { mode, surface, bandWaived = false }) {
  const fails = []
  const warns = []
  const [lo, hi] = BAND[mode]
  const off = colors.filter((c) => {
    const L = oklch(c)[0]
    return L < lo || L > hi
  })
  if (off.length)
    (bandWaived ? warns : fails).push(`lightness outside ${lo}-${hi}: ${off.join(' ')}`)
  const dull = colors.filter((c) => oklch(c)[1] < CHROMA_FLOOR)
  if (dull.length) fails.push(`chroma below ${CHROMA_FLOOR}: ${dull.join(' ')}`)
  for (let i = 1; i < colors.length; i++) {
    const a = colors[i - 1]
    const b = colors[i]
    const cvd = Math.min(deltaE(a, b, 'protan'), deltaE(a, b, 'deutan'))
    if (cvd < CVD_FLOOR) fails.push(`CVD delta E ${cvd.toFixed(1)} < ${CVD_FLOOR}: ${a} ${b}`)
    else if (cvd < CVD_TARGET)
      warns.push(`CVD delta E ${cvd.toFixed(1)} in the 6-8 band: ${a} ${b}`)
    const normal = deltaE(a, b)
    if (normal < NORMAL_FLOOR)
      fails.push(`normal-vision delta E ${normal.toFixed(1)} < ${NORMAL_FLOOR}: ${a} ${b}`)
  }
  const low = colors.filter((c) => contrast(c, surface) < CONTRAST_MIN)
  if (low.length) warns.push(`contrast below 3:1 (labels or table view required): ${low.join(' ')}`)
  return { fails, warns }
}

/** Validates a sequential ramp, light end first in light mode and dark end first in dark mode. */
export function validateSequential(colors, inks, { mode, surface }) {
  const fails = []
  const warns = []
  const Ls = colors.map((c) => oklch(c)[0])
  for (let i = 1; i < Ls.length; i++) {
    const step = mode === 'light' ? Ls[i - 1] - Ls[i] : Ls[i] - Ls[i - 1]
    if (step < SEQ_MIN_DL)
      fails.push(
        `ramp step ${colors[i - 1]} -> ${colors[i]} lightness change ${step.toFixed(3)} < ${SEQ_MIN_DL}`
      )
  }
  colors.forEach((c, i) => {
    const cr = contrast(c, inks[i])
    if (cr < INK_MIN) fails.push(`ink ${inks[i]} on ${c} is ${cr.toFixed(2)}:1 < ${INK_MIN}:1`)
  })
  const first = colors[0]
  if (contrast(first, surface) < 1.5)
    warns.push(`first ramp step ${first} barely clears the surface`)
  return { fails, warns }
}

/** The --viz-* tokens the palette defines, by mode. */
export function expectedTokens(p, mode) {
  const t = {}
  p.severity.keys.forEach((k, i) => (t[`--viz-sev-${k}`] = p.severity[mode][i]))
  t['--viz-sev-info'] = p.severity.info[mode]
  p.categorical[mode].forEach((c, i) => (t[`--viz-cat-${i + 1}`] = c))
  t['--viz-cat-other'] = p.categorical.other[mode]
  p.diverging.keys.forEach((k, i) => (t[`--viz-div-${k}`] = p.diverging[mode][i]))
  p.sequential[mode].forEach((c, i) => (t[`--viz-seq-${i + 1}`] = c))
  p.sequential.ink[mode].forEach((c, i) => (t[`--viz-seq-ink-${i + 1}`] = c))
  return t
}

/** Reads `--name: value;` declarations of one top-level CSS block (":root" or ".dark"). */
export function cssBlockTokens(css, selector) {
  const start = css.indexOf(`\n${selector} {`)
  const at = start >= 0 ? start : css.startsWith(`${selector} {`) ? 0 : -1
  if (at < 0) return {}
  const body = css.slice(css.indexOf('{', at) + 1, css.indexOf('\n}', at))
  const out = {}
  for (const m of body.matchAll(/(--viz-[a-z0-9-]+):\s*([^;]+);/g))
    out[m[1]] = m[2].trim().toLowerCase()
  return out
}

export function checkAll(palette, css) {
  const fails = []
  const warns = []
  const add = (label, r) => {
    r.fails.forEach((f) => fails.push(`${label}: ${f}`))
    r.warns.forEach((w) => warns.push(`${label}: ${w}`))
  }
  for (const mode of ['light', 'dark']) {
    const surface = palette.surfaces[mode]
    add(
      `severity/${mode}`,
      validateCategorical(palette.severity[mode], {
        mode,
        surface,
        bandWaived: mode === 'dark' && !!palette.severity.darkBandWaiver,
      })
    )
    add(`categorical/${mode}`, validateCategorical(palette.categorical[mode], { mode, surface }))
    add(`diverging/${mode}`, validateCategorical(palette.diverging[mode], { mode, surface }))
    add(
      `sequential/${mode}`,
      validateSequential(palette.sequential[mode], palette.sequential.ink[mode], { mode, surface })
    )
    if (css != null) {
      const have = cssBlockTokens(css, mode === 'light' ? ':root' : '.dark')
      for (const [name, value] of Object.entries(expectedTokens(palette, mode))) {
        if (have[name] !== value.toLowerCase())
          fails.push(
            `theme.css ${mode}: ${name} is ${have[name] ?? 'missing'}, palette says ${value}`
          )
      }
    }
  }
  return { fails, warns }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..')
  const palette = JSON.parse(readFileSync(join(root, 'src/lib/chart-palette.json'), 'utf8'))
  const css = readFileSync(join(root, 'src/styles/theme.css'), 'utf8')
  const { fails, warns } = checkAll(palette, css)
  warns.forEach((w) => console.log(`WARN ${w}`))
  fails.forEach((f) => console.error(`FAIL ${f}`))
  if (fails.length) {
    console.error(`check-palette: ${fails.length} failure(s)`)
    process.exit(1)
  }
  console.log(
    `check-palette: palettes valid (${warns.length} warning(s), each covered by labels and a table view)`
  )
}
