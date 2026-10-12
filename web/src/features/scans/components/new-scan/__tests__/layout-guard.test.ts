/**
 * Layout guard for the New Scan wizard (the browser check is
 * e2e/specs/17-new-scan-layout.spec.ts): a fieldset is min-content wide by
 * default, and one long truncated line inside one made the dialog body
 * scroll sideways. The global reset and the wizard's fieldsets must keep it
 * shrinkable.
 */
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const ROOT = join(__dirname, '..', '..', '..', '..', '..')

describe('New Scan layout guard', () => {
  it('the base styles let every fieldset shrink', () => {
    const css = readFileSync(join(ROOT, 'app', 'globals.css'), 'utf8')
    expect(css).toMatch(/fieldset\s*\{\s*min-width:\s*0;?\s*\}/)
  })

  it('every bordered fieldset in the wizard is min-w-0', () => {
    const dir = join(ROOT, 'features', 'scans', 'components', 'new-scan')
    for (const f of readdirSync(dir).filter((n) => n.endsWith('.tsx'))) {
      const src = readFileSync(join(dir, f), 'utf8')
      for (const m of src.matchAll(/<fieldset className="([^"]*)"/g)) {
        if (m[1].includes('border')) expect(m[1], `${f}: ${m[0]}`).toContain('min-w-0')
      }
    }
  })
})
