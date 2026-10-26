import { afterEach, describe, expect, it } from 'vitest'
import { TRIAGE_KEYS, triageActionFor } from '../triage-keys'

const noDialog = { querySelector: () => null }

function el(html: string, pick = '[data-pick]'): Element {
  const host = document.createElement('div')
  host.innerHTML = html
  document.body.appendChild(host)
  return host.querySelector(pick) ?? host.firstElementChild!
}

afterEach(() => {
  document.body.innerHTML = ''
})

describe('triage keys', () => {
  it.each([
    ['c', 'confirm'],
    ['f', 'falsePositive'],
    ['a', 'accept'],
    ['o', 'assign'],
    ['s', 'skip'],
    ['m', 'task'],
    ['r', 'retest'],
    ['u', 'undo'],
    ['j', 'next'],
    ['k', 'prev'],
    ['e', 'evidence'],
    ['Enter', 'openPage'],
    ['?', 'help'],
    ['Escape', 'exit'],
  ])('%s is %s', (key, action) => {
    expect(triageActionFor({ key, target: document.body }, noDialog)).toBe(action)
  })

  it('every action has one key and the keys are unique', () => {
    const keys = TRIAGE_KEYS.map((k) => k.key)
    expect(new Set(keys).size).toBe(keys.length)
    expect(new Set(TRIAGE_KEYS.map((k) => k.action)).size).toBe(keys.length)
  })

  it('ignores chords, repeats, handled events and other keys', () => {
    for (const mod of ['metaKey', 'ctrlKey', 'altKey', 'repeat', 'defaultPrevented']) {
      expect(triageActionFor({ key: 'c', [mod]: true, target: document.body }, noDialog)).toBeNull()
    }
    expect(triageActionFor({ key: 'x', target: document.body }, noDialog)).toBeNull()
    expect(triageActionFor({ key: 'C', target: document.body }, noDialog)).toBeNull()
  })

  it.each([
    '<input data-pick />',
    '<textarea data-pick></textarea>',
    '<select data-pick></select>',
    '<div contenteditable="true" data-pick></div>',
    '<div role="combobox" data-pick></div>',
    '<button role="combobox" aria-expanded="true" data-pick>x</button>',
    '<div role="listbox"><div role="option" data-pick></div></div>',
    '<div role="menu"><div role="menuitem" data-pick></div></div>',
    '<div role="dialog"><button data-pick>x</button></div>',
    '<div role="alertdialog"><span data-pick>x</span></div>',
  ])('does nothing while focus is in %s', (html) => {
    const target = el(html)
    for (const key of ['c', 'f', 'a', 's', 'j', 'Enter', 'Escape']) {
      expect(triageActionFor({ key, target }, noDialog)).toBeNull()
    }
  })

  it('letters still act on a focused page button; Enter presses the button', () => {
    const target = el('<button data-pick>Next</button>')
    expect(triageActionFor({ key: 'c', target }, noDialog)).toBe('confirm')
    expect(triageActionFor({ key: 'Enter', target }, noDialog)).toBeNull()
  })

  it('letters act on the closed trigger of a picker, not on an open one', () => {
    const closed = el('<button role="combobox" aria-expanded="false" data-pick>Pick</button>')
    expect(triageActionFor({ key: 'c', target: closed }, noDialog)).toBe('confirm')
    const open = el('<button role="combobox" aria-expanded="true" data-pick>Pick</button>')
    expect(triageActionFor({ key: 'c', target: open }, noDialog)).toBeNull()
    const field = el('<input role="combobox" aria-expanded="false" data-pick />')
    expect(triageActionFor({ key: 'c', target: field }, noDialog)).toBeNull()
  })

  it('a closing picker (still mounted for its exit animation) no longer owns the keys', () => {
    const target = el('<div role="dialog" data-state="closed"><input data-pick /></div>')
    expect(triageActionFor({ key: 'u', target }, document)).toBe('undo')
    const open = el('<div role="dialog" data-state="open"><input data-pick /></div>')
    expect(triageActionFor({ key: 'u', target: open }, document)).toBeNull()
  })

  it('does nothing while a dialog is open anywhere on the page', () => {
    const doc = { querySelector: (s: string) => (s.includes('dialog') ? document.body : null) }
    expect(triageActionFor({ key: 'c', target: document.body }, doc)).toBeNull()
    expect(triageActionFor({ key: 'Escape', target: document.body }, doc)).toBeNull()
  })
})
