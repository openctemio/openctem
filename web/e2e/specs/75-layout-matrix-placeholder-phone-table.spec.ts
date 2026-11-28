import { test, expect, type Page } from '@playwright/test'
import { findMatrixBreaks } from '../helpers/layout-matrix'

/**
 * Self-test of two report-only layout matrix detectors
 * (helpers/layout-matrix.ts, UI audit 2026-11-27 D5 and D9):
 * - unfilledPlaceholder: visible text that still shows a `{name}` of its
 *   catalog string ("Imports choose it as format {format}.").
 * - phoneTable: on a phone, a table that scrolls sideways or a cell taller
 *   than three lines (Settings > Sensor products and Scope > Letters drew a
 *   raw table at 390 px).
 */

const doc = (body: string) =>
  `<!doctype html><html><body style="margin:0;font:14px/20px sans-serif">${body}</body></html>`

async function at(p: Page, body: string, width = 1440) {
  await p.setViewportSize({ width, height: 900 })
  await p.setContent(doc(`<main style="padding:16px">${body}</main>`))
  return findMatrixBreaks(p)
}

const row = (cells: string[]) =>
  `<tr>${cells.map((c) => `<td style="padding:8px">${c}</td>`).join('')}</tr>`

test.describe('layout matrix detector: unfilled placeholder', { tag: ['@shell'] }, () => {
  test('flags a sentence that shows its placeholder', async ({ page }) => {
    const found = (await at(page, '<p>Imports choose it as format {format}.</p>'))
      .unfilledPlaceholder
    expect(found.join('\n')).toMatch(/shows \{format\}/)
  })

  test('is quiet for filled text, code, a field value and JSON', async ({ page }) => {
    const body = `<p>Imports choose it as format Nessus CSV.</p>
      <p>Write variables as <code>{name}</code>.</p>
      <pre>{"a": 1}</pre>
      <textarea>{host}</textarea>
      <p>Set {"a": 1} in the body</p>`
    expect((await at(page, body)).unfilledPlaceholder).toEqual([])
  })

  test('is quiet for hidden text', async ({ page }) => {
    const body = `<p style="display:none">Hidden {format}</p><span class="sr" aria-hidden="true">{x}</span>`
    expect((await at(page, body)).unfilledPlaceholder).toEqual([])
  })
})

test.describe('layout matrix detector: phone table', { tag: ['@shell'] }, () => {
  const wide = `<div style="overflow-x:auto"><table style="border-collapse:collapse;white-space:nowrap">
    ${row(['example-edge-agent', 'v1.4.0', 'v1.2.0', 'Nov 27, 2026, 9:20 AM', 'Delete'])}</table></div>`

  test('flags a table that scrolls sideways on a phone', async ({ page }) => {
    const found = (await at(page, wide, 390)).phoneTable
    expect(found.join('\n')).toMatch(/table \d+px wide in \d+px/)
  })

  test('flags a cell squeezed into more than three lines on a phone', async ({ page }) => {
    const tall = `<table style="width:100%;border-collapse:collapse">${row([
      'Q4 penetration testing authorization for the external estate of every subsidiary and partner network',
      'Example Holdings legal department',
      'Status',
    ])}</table>`
    const found = (await at(page, tall, 390)).phoneTable
    expect(found.join('\n')).toMatch(/over 3 lines/)
  })

  test('is quiet on a desktop and for a phone list of cards', async ({ page }) => {
    expect((await at(page, wide, 1440)).phoneTable).toEqual([])
    const cards = `<ul style="list-style:none;padding:0">
      <li style="border:1px solid #ddd;padding:12px">example-edge-agent<br>v1.4.0</li></ul>`
    expect((await at(page, cards, 390)).phoneTable).toEqual([])
  })
})
