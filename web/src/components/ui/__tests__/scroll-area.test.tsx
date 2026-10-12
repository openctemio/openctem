/**
 * ScrollArea: a max-h-* on the root must bound the scroll area.
 *
 * Radix sizes the viewport at height:100% of the root. With only a max-height
 * on the root that percentage resolves to auto, so the viewport grew to its
 * content and the rows spilled over whatever followed (the New Scan targets
 * list ran over "Custom Targets" and the summary). The viewport now inherits
 * the root's max-height, and its content wrapper is a block so truncate works.
 */
import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { ScrollArea } from '../scroll-area'

describe('ScrollArea', () => {
  it('caps the viewport at the root max-height and lays content out as a block', () => {
    const { container } = render(
      <ScrollArea className="max-h-48">
        <p>row</p>
      </ScrollArea>
    )
    const root = container.querySelector('[data-slot="scroll-area"]')
    const viewport = container.querySelector('[data-slot="scroll-area-viewport"]')
    expect(root?.className).toContain('max-h-48')
    expect(viewport?.className).toContain('max-h-[inherit]')
    expect(viewport?.className).toContain('[&>div]:!block')
  })
})

const SRC = join(__dirname, '../../..')

function* tsxFiles(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (name === 'node_modules' || name === '__tests__') continue
    if (statSync(p).isDirectory()) yield* tsxFiles(p)
    else if (name.endsWith('.tsx')) yield p
  }
}

describe('ScrollArea governance', () => {
  // The viewport takes the root's whole max-height, so vertical padding on a
  // capped root pushes the viewport past the root's edge. Pad a child instead.
  it('has no vertical padding on a root that carries a max-height', () => {
    const offenders: string[] = []
    const tag = /<ScrollArea\b[^>]*>/g
    const vPad = /(?:^|\s)(?:p|py|pt|pb)-\S+/
    for (const file of tsxFiles(SRC)) {
      const src = readFileSync(file, 'utf8')
      for (const open of src.match(tag) ?? []) {
        const cls = open.match(/className="([^"]*)"/)?.[1] ?? ''
        const capped = /(?:^|\s)max-h-/.test(cls) || /maxHeight/.test(open)
        if (capped && vPad.test(cls)) offenders.push(`${relative(SRC, file)}: ${cls}`)
      }
    }
    expect(offenders).toEqual([])
  })
})
