import { test, expect, type Page } from '@playwright/test'
import { findMatrixBreaks } from '../helpers/layout-matrix'

/**
 * Self-test of the layout matrix's list-shape detectors
 * (helpers/layout-matrix.ts), from the UI audit of 2026-11-27:
 *   - repeatedRows (D1): the attack surface's "Fix first" listed "Redis
 *     reachable from the internet without authentication" ten times, only
 *     the address changing; the Changes tab listed 867 "Lookalike domain
 *     registered" rows one by one.
 *   - cardPerRow (D3): Exposure chains drew each chain as a 170 px bordered
 *     card, 95 of them stacked, most holding one node.
 * Each flags its defect and stays quiet for the right layout.
 */

const doc = (body: string) =>
  `<!doctype html><html><body style="margin:0;font:14px sans-serif">${body}</body></html>`

async function at(p: Page, body: string, width = 1440) {
  await p.setViewportSize({ width, height: 900 })
  await p.setContent(doc(`<main style="padding:16px">${body}</main>`))
  return findMatrixBreaks(p)
}

const redis = (ip: string) =>
  `<li><span>Critical</span> Redis reachable from the internet without authentication (port 6379/tcp) <a href="#">${ip}:6379:tcp</a> 2 hours ago</li>`

const box = (inner: string) =>
  `<div style="border:1px solid #ddd;border-radius:8px;padding:16px">${inner}</div>`

test.describe('layout matrix detector: repeated rows', { tag: ['@shell'] }, () => {
  test('flags rows that differ only by an address', async ({ page }) => {
    const ips = ['198.51.100.50', '198.51.100.47', '2001:db8:4::b', '198.51.100.42']
    const found = await at(page, `<ul>${ips.map(redis).join('')}</ul>`)
    expect(found.repeatedRows.join('\n')).toMatch(/4 rows read the same "Critical Redis reachable/)
  })

  test('is quiet for one row per issue with its count', async ({ page }) => {
    const rows = `<ul>
      <li>Critical Redis reachable from the internet without authentication 198.51.100.50 +9 more</li>
      <li>High Certificate expired on www.example.com 3 days ago</li>
      <li>Medium Dangling CNAME on old.example.com to an unclaimed bucket</li>
    </ul>`
    expect((await at(page, rows)).repeatedRows).toEqual([])
  })

  test('is quiet for short rows that repeat by design (dates, tags)', async ({ page }) => {
    const rows = `<ul>${['1', '2', '3', '4'].map((d) => `<li>Day ${d}</li>`).join('')}</ul>`
    expect((await at(page, rows)).repeatedRows).toEqual([])
  })

  test('counts only consecutive rows', async ({ page }) => {
    const rows = `<ul>${redis('198.51.100.1')}${redis('198.51.100.2')}
      <li>High Certificate expired on www.example.com three days ago</li>
      ${redis('198.51.100.3')}</ul>`
    expect((await at(page, rows)).repeatedRows).toEqual([])
  })
})

test.describe('layout matrix detector: card per row', { tag: ['@shell'] }, () => {
  test('flags five full-width short boxes stacked as a list', async ({ page }) => {
    const stacked = `<div style="display:flex;flex-direction:column;gap:12px">${Array.from(
      { length: 6 },
      (_, i) => box(`<p style="margin:0">${i + 1}. 192.0.2.${i} Entry KEV</p>`)
    ).join('')}</div>`
    expect((await at(page, stacked)).cardPerRow.join('\n')).toMatch(
      /6 framed cards stacked one per row/
    )
  })

  test('is quiet for one bordered list with rows divided by lines', async ({ page }) => {
    const list = `<ol style="border:1px solid #ddd;border-radius:8px;list-style:none;margin:0;padding:0">${Array.from(
      { length: 6 },
      (_, i) =>
        `<li style="border-top:${i ? '1px solid #ddd' : '0'};padding:12px">${i + 1}. 192.0.2.${i}</li>`
    ).join('')}</ol>`
    expect((await at(page, list)).cardPerRow).toEqual([])
  })

  test('is quiet for a grid of cards side by side', async ({ page }) => {
    const grid = `<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px">${Array.from(
      { length: 6 },
      (_, i) => box(`Template ${i}`)
    ).join('')}</div>`
    expect((await at(page, grid)).cardPerRow).toEqual([])
  })

  test('is quiet for tall section cards (a settings page)', async ({ page }) => {
    const sections = `<div style="display:flex;flex-direction:column;gap:16px">${Array.from(
      { length: 5 },
      (_, i) => box(`<h2>Section ${i}</h2><div style="height:220px"></div>`)
    ).join('')}</div>`
    expect((await at(page, sections)).cardPerRow).toEqual([])
  })
})
