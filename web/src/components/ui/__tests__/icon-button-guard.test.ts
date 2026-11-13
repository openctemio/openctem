import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { findIconButtons } from '../../../../scripts/icon-buttons.mjs'

/**
 * Icon-only buttons are squares at every size ("Sizes" in
 * web/docs/ui-style-contract.md). A <Button> whose content is only an icon
 * takes an icon size (icon, icon-sm, xs); one that is icon-only below a
 * breakpoint sets iconOnlyBelow. Fix with `node scripts/icon-buttons.mjs --write`.
 */
describe('icon-only buttons', () => {
  it('every icon-only Button has a square size', () => {
    const { report } = findIconButtons(path.resolve(__dirname, '../../../..'))
    expect(report).toEqual([])
  }, 60_000)
})
