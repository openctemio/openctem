/**
 * Guard: a page never hides its header description on a phone (hidden or
 * screen-reader only). Sibling tabs
 * then keep one header height (the tab row does not jump), and every page
 * tells a phone user what it is for, as it does on a desktop.
 */
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) {
      if (name === '__tests__' || name === 'node_modules') continue
      sources(full, out)
    } else if (name.endsWith('.tsx')) out.push(full)
  }
  return out
}

describe('PageHeader description', () => {
  it('is never hidden below a width by its caller', () => {
    const offenders: string[] = []
    for (const file of sources(join(process.cwd(), 'src'))) {
      const src = readFileSync(file, 'utf8')
      for (const m of src.matchAll(
        /description=\{\s*<[a-z]+\s+className=\{?[^>]*\bmax-(?:sm|md|lg):(?:hidden|sr-only)\b/g
      ))
        offenders.push(`${file.slice(process.cwd().length + 1)} @${m.index}`)
    }
    expect(offenders).toEqual([])
  })
})
