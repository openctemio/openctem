/**
 * The page's input modality gates every `focus-visible:` ring
 * (src/lib/input-modality.ts, src/app/globals.css): after a pointer press no
 * control except a text field draws the ring, so a focus moved by script
 * (the sidebar sheet focusing the current page's row, a select giving the
 * focus back to its trigger) shows no ring at rest; a key press brings it
 * back before the focus moves.
 */
import { afterEach, describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { INPUT_MODALITY_ATTRIBUTE, installInputModality, isNavigationKey } from '../input-modality'

const root = () => document.documentElement
const mode = () => root().getAttribute(INPUT_MODALITY_ATTRIBUTE)

let cleanup: (() => void) | undefined
afterEach(() => {
  cleanup?.()
  cleanup = undefined
  root().removeAttribute(INPUT_MODALITY_ATTRIBUTE)
})

describe('input modality', () => {
  it('starts as pointer: a page is opened with a pointer, a key switches it', () => {
    cleanup = installInputModality()
    expect(mode()).toBe('pointer')
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab' }))
    expect(mode()).toBe('keyboard')
    window.dispatchEvent(new Event('pointerdown'))
    expect(mode()).toBe('pointer')
  })

  it('hears a key a component stops (capture phase)', () => {
    cleanup = installInputModality()
    const menu = document.createElement('div')
    document.body.append(menu)
    menu.addEventListener('keydown', (e) => e.stopPropagation())
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }))
    expect(mode()).toBe('keyboard')
    menu.remove()
  })

  it('ignores key chords and modifier keys pressed alone', () => {
    expect(isNavigationKey({ key: 'c', metaKey: true, ctrlKey: false, altKey: false })).toBe(false)
    expect(isNavigationKey({ key: 'b', metaKey: false, ctrlKey: true, altKey: false })).toBe(false)
    expect(isNavigationKey({ key: 'Shift', metaKey: false, ctrlKey: false, altKey: false })).toBe(
      false
    )
    expect(isNavigationKey({ key: 'Tab', metaKey: false, ctrlKey: false, altKey: false })).toBe(
      true
    )
    expect(isNavigationKey({ key: 'Enter', metaKey: false, ctrlKey: false, altKey: false })).toBe(
      true
    )
  })

  it('installs once and stops listening on cleanup', () => {
    const first = installInputModality()
    expect(installInputModality()).toBe(first)
    first()
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab' }))
    expect(mode()).toBe('pointer')
  })

  it('keeps a modality set before it ran', () => {
    root().setAttribute(INPUT_MODALITY_ATTRIBUTE, 'keyboard')
    cleanup = installInputModality()
    expect(mode()).toBe('keyboard')
  })
})

describe('the focus-visible variant', () => {
  const css = readFileSync(path.resolve(__dirname, '../../app/globals.css'), 'utf8')

  it('replaces the built-in variant, gated on the pointer modality', () => {
    const block = css.slice(css.indexOf('@custom-variant focus-visible'))
    expect(block).toMatch(/&:focus-visible:not\(\s*:where\(\s*\[data-input='pointer'\]/)
    expect(block.slice(0, block.indexOf('@slot'))).toContain('textarea')
  })

  it('also hides the browser outline after a pointer press, except on a text field', () => {
    expect(css).toMatch(/\[data-input='pointer'\]\s*:focus-visible:not\(\s*textarea/)
  })

  it('is installed for the app and the console (one Providers)', () => {
    const providers = readFileSync(path.resolve(__dirname, '../../app/providers.tsx'), 'utf8')
    expect(providers).toContain('installInputModality()')
  })
})
