import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { SPACING_NAMES, TYPE_SCALE, cn } from '../utils'

/**
 * cn() must treat the theme's own names as what they are: a type role is a
 * size (never dropped beside a colour), a control height conflicts with
 * another height, the dialog radius with another radius.
 */
describe('cn() and the theme names', () => {
  it('keeps a type role next to a text colour, and lets a later size win', () => {
    expect(cn('text-figure tabular-nums', 'text-success')).toBe(
      'text-figure tabular-nums text-success'
    )
    expect(cn('text-cap-m', 'text-muted-foreground')).toBe('text-cap-m text-muted-foreground')
    expect(cn('text-body font-medium', 'text-dense')).toBe('font-medium text-dense')
    expect(cn('text-sm', 'text-page')).toBe('text-page')
  })

  it('merges control and row heights like any height', () => {
    expect(cn('h-control px-3', 'h-7')).toBe('px-3 h-7')
    expect(cn('h-9', 'h-control-sm')).toBe('h-control-sm')
    expect(cn('size-control', 'max-md:size-control-touch', 'size-8')).toBe(
      'max-md:size-control-touch size-8'
    )
    expect(cn('rounded-lg', 'rounded-dialog')).toBe('rounded-dialog')
  })

  it('knows every --text-* role and --spacing-* name of theme.css', () => {
    const css = readFileSync(path.resolve(__dirname, '../../styles/theme.css'), 'utf8')
    const theme = css.slice(css.indexOf('@theme inline {'))
    const roles = [...theme.matchAll(/^\s*--text-([a-z]+(?:-[a-z]+)*):/gm)].map((m) => m[1])
    const spacing = [...theme.matchAll(/^\s*--spacing-([a-z]+(?:-[a-z]+)*):/gm)].map((m) => m[1])
    expect([...TYPE_SCALE].sort()).toEqual([...new Set(roles)].sort())
    expect([...SPACING_NAMES].sort()).toEqual([...new Set(spacing)].sort())
  })
})
