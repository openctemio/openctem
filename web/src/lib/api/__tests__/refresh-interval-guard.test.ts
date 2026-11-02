import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

/**
 * Polling guard. SWR restarts its polling timer whenever the
 * `refreshInterval` it is given changes identity. An inline arrow
 * (`refreshInterval: (data) => ...`) is a new function on every render, so a
 * component that re-renders faster than the interval (a 1 s countdown, a
 * "seen 4 s ago" clock) resets the timer before it fires and never polls
 * again. That stopped the Add sensor dialog from ever seeing the sensor.
 *
 * A function-valued interval is declared at module scope (or memoized); a
 * number may stay inline.
 */
const WEB = join(__dirname, '..', '..', '..', '..')
const ROOTS = [join(WEB, 'src'), join(WEB, 'console', 'src')]

function walk(path: string, out: string[]) {
  let st
  try {
    st = statSync(path)
  } catch {
    return
  }
  if (st.isDirectory()) {
    for (const name of readdirSync(path)) {
      if (name === 'node_modules' || name.startsWith('.') || name === 'generated') continue
      walk(join(path, name), out)
    }
  } else if (/\.tsx?$/.test(path) && !/\.test\.tsx?$/.test(path)) {
    out.push(path)
  }
}

const INLINE_INTERVAL =
  /refreshInterval\s*(?::|=\{)\s*(?:\([^)]*\)|\w+)\s*(?::\s*\w+\s*)?=>|refreshInterval\s*(?::|=\{)\s*function\b/

describe('refreshInterval guard', () => {
  it('finds source files', () => {
    const files: string[] = []
    for (const root of ROOTS) walk(root, files)
    expect(files.length).toBeGreaterThan(100)
  })

  it('no inline function as an SWR refreshInterval', () => {
    const files: string[] = []
    for (const root of ROOTS) walk(root, files)
    const offenders: string[] = []
    for (const file of files) {
      const lines = readFileSync(file, 'utf8').split('\n')
      lines.forEach((line, i) => {
        if (INLINE_INTERVAL.test(line)) {
          offenders.push(`${relative(WEB, file).split(sep).join('/')}:${i + 1}`)
        }
      })
    }
    expect(offenders).toEqual([])
  })

  it('the pattern catches the forms it is meant to', () => {
    expect(INLINE_INTERVAL.test('refreshInterval: (latest) => (latest ? 0 : 3000),')).toBe(true)
    expect(INLINE_INTERVAL.test('refreshInterval: (s?: Sensor) => 0,')).toBe(true)
    expect(INLINE_INTERVAL.test('refreshInterval: d => 0,')).toBe(true)
    expect(INLINE_INTERVAL.test('refreshInterval={() => 1000}')).toBe(true)
    expect(INLINE_INTERVAL.test('refreshInterval: function (d) { return 0 },')).toBe(true)
    expect(INLINE_INTERVAL.test('refreshInterval: expectationRefreshInterval,')).toBe(false)
    expect(INLINE_INTERVAL.test('refreshInterval: live ? 3000 : 0,')).toBe(false)
  })
})
