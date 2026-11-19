/**
 * The empty table cell lives once, in the shared kit: every app (tenant and
 * console) imports it from there, and no feature folder keeps its own copy.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { EmptyCell } from '../empty-cell'
import { RelativeTime } from '../relative-time'

const WEB = join(__dirname, '../../../../..')
const ROOTS = [join(WEB, 'src'), join(WEB, 'console/src')]
const KIT = 'src/features/shared/components/empty-cell.tsx'
// A dash written as JSX text: `>-<`, `>—<`, or a line holding only a dash.
const HAND_DASH = />\s*[-–—]\s*<|^\s*[-–—]\s*$/m
// Files allowed a dash of their own: the kit cell itself, and a metric tile
// whose figure failed to load (a tile, not a cell; the error is its hover text).
const OWN_DASH = new Set([KIT, 'src/features/shared/components/metric-strip.tsx'])

function sources(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '__tests__') continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) sources(full, out)
    else if (/\.tsx?$/.test(entry)) out.push(full)
  }
  return out
}

describe('EmptyCell', () => {
  it('is a muted dash with a hover text saying why', () => {
    render(<EmptyCell title="No owner yet" />)
    const cell = screen.getByTitle('No owner yet')
    expect(cell).toHaveTextContent('—')
    expect(cell).toHaveAttribute('data-slot', 'empty-cell')
    expect(cell.className).toContain('text-muted-foreground')
  })

  it('is defined once, in the shared kit, and imported from there', () => {
    const offenders: string[] = []
    for (const root of ROOTS) {
      for (const file of sources(root)) {
        const rel = relative(WEB, file)
        if (rel === KIT) continue
        const src = readFileSync(file, 'utf8')
        if (/export\s+(function|const)\s+EmptyCell\b/.test(src))
          offenders.push(`${rel}: defines EmptyCell`)
        const imports = src.match(/import\s*\{[^}]*\bEmptyCell\b[^}]*\}\s*from\s*'([^']+)'/g) ?? []
        for (const line of imports) {
          const from = line.match(/from\s*'([^']+)'/)?.[1] ?? ''
          const kitPath =
            from.startsWith('.') &&
            relative(WEB, resolve(dirname(file), from)) === KIT.replace(/\.tsx$/, '')
          if (!kitPath && !/^@\/features\/shared(\/components(\/empty-cell)?)?$/.test(from))
            offenders.push(`${rel}: imports EmptyCell from ${from}`)
        }
      }
    }
    expect(offenders).toEqual([])
  })

  it('is what the kit draws for an empty value: no shared component writes its own dash', () => {
    const offenders = sources(join(WEB, 'src/features/shared/components'))
      .map((file) => relative(WEB, file))
      .filter((rel) => !OWN_DASH.has(rel) && HAND_DASH.test(readFileSync(join(WEB, rel), 'utf8')))
    expect(offenders).toEqual([])
  })

  it('fills the technologies list, which wrote its own dashes', () => {
    const src = readFileSync(
      join(WEB, 'src/features/attack-surface/components/easm-technologies.tsx'),
      'utf8'
    )
    expect(src).not.toMatch(HAND_DASH)
  })

  it('is what a missing time renders', () => {
    const { container } = render(<RelativeTime date={null} />)
    expect(container.querySelector('[data-slot=empty-cell]')).not.toBeNull()
  })
})
