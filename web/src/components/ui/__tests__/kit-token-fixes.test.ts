import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

import { badgeVariants } from '../badge'
import { buttonVariants } from '../button'

/**
 * Kit defects that hid a state in one theme. Each test fails on the code that
 * had the defect.
 */

const UI = path.resolve(__dirname, '..')
const read = (name: string) => readFileSync(path.join(UI, name), 'utf8')

describe('kit token use', () => {
  it('never wraps a colour token in hsl(): the tokens are hex values, so the rule is dropped', () => {
    // sidebar.tsx drew its outline edge with hsl(var(--sidebar-border)): no edge at all.
    const offenders = readdirSync(UI)
      .filter((f) => /\.tsx?$/.test(f))
      .filter((f) => /hsl\(var\(--/.test(read(f)))
    expect(offenders).toEqual([])
  })

  it('highlights menu, select and command rows with --hov, which is visible on a dark popover', () => {
    for (const f of ['dropdown-menu.tsx', 'select.tsx', 'command.tsx']) {
      const src = read(f)
      expect(src, f).not.toMatch(/(focus|data-\[selected=true\]|data-\[state=open\]):bg-accent\b/)
      expect(src, f).toMatch(/:bg-hov\b/)
    }
  })

  it('puts destructive-foreground on the destructive button and badge in both themes', () => {
    for (const cls of [
      buttonVariants({ variant: 'destructive' }),
      badgeVariants({ variant: 'destructive' }),
    ]) {
      expect(cls).toContain('bg-destructive')
      expect(cls).toContain('text-destructive-foreground')
      // White on a 60% fill in dark was not the pair the contrast test checks.
      expect(cls).not.toContain('text-white')
      expect(cls).not.toContain('dark:bg-destructive/60')
    }
  })
})
