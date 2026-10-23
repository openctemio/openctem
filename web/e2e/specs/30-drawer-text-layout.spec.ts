import { test, expect } from '../fixtures/authenticated-page'
import type { Locator, Page, TestInfo } from '@playwright/test'
import { openFirstAssetSheet } from '../helpers/assets'
import { firstDataRow } from '../helpers/table'

/**
 * Drawer text layout (research/244). In an open drawer:
 *
 *  a. a single word of 24 characters or fewer is never broken over two lines
 *     (a squeezed column breaks "Technologies" letter by letter);
 *  b. every metadata line (data-slot="meta-line") has one font size across
 *     all of its text;
 *  c. no visible text is smaller than 12px.
 *
 * Runs at a phone (390) and a desktop (1440) width over the asset drawer
 * (every tab), the finding drawer, a scan run view and a sensor drawer.
 * Each skips when the organization has no such data. Read-only: nothing is
 * created or changed.
 */

const SIZES = [
  { name: 'phone', width: 390, height: 844 },
  { name: 'desktop', width: 1440, height: 900 },
]

async function shot(page: Page, info: TestInfo, name: string) {
  await info.attach(name, { body: await page.screenshot(), contentType: 'image/png' })
}

type Violations = { brokenWords: string[]; mixedMeta: string[]; tiny: string[] }

/** Measure the text inside `root`; runs in the page. */
async function measure(root: Locator): Promise<Violations> {
  return root.evaluate((el): Violations => {
    const out: Violations = { brokenWords: [], mixedMeta: [], tiny: [] }
    const visible = (node: Element) => {
      const r = node.getBoundingClientRect()
      if (r.width === 0 || r.height === 0) return false
      const cs = getComputedStyle(node)
      return cs.visibility !== 'hidden' && cs.display !== 'none' && cs.opacity !== '0'
    }
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT)
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = n.textContent ?? ''
      const parent = n.parentElement
      if (!parent || !text.trim() || !visible(parent)) continue
      if (parent.closest('script,style,svg,[aria-hidden="true"]')) continue
      const px = parseFloat(getComputedStyle(parent).fontSize)
      if (px < 11.99) out.tiny.push(`${px}px "${text.trim().slice(0, 40)}"`)
      const trimmed = text.trim()
      if (trimmed.length <= 24 && !/\s/.test(trimmed)) {
        const range = document.createRange()
        range.selectNodeContents(n)
        const tops = new Set([...range.getClientRects()].map((r) => Math.round(r.top)))
        if (tops.size > 1) out.brokenWords.push(trimmed)
      }
    }
    for (const line of el.querySelectorAll('[data-slot="meta-line"]')) {
      const sizes = new Set<number>()
      const w = document.createTreeWalker(line, NodeFilter.SHOW_TEXT)
      for (let n = w.nextNode(); n; n = w.nextNode()) {
        const p = n.parentElement
        if (p && (n.textContent ?? '').trim() && visible(p)) {
          sizes.add(parseFloat(getComputedStyle(p).fontSize))
        }
      }
      if (sizes.size > 1) {
        out.mixedMeta.push(`${[...sizes].join('/')}px "${(line.textContent ?? '').slice(0, 60)}"`)
      }
    }
    return out
  })
}

async function check(root: Locator, label: string) {
  const v = await measure(root)
  expect(v.brokenWords, `${label}: words broken over two lines`).toEqual([])
  expect(v.mixedMeta, `${label}: a meta line mixes font sizes`).toEqual([])
  expect(v.tiny, `${label}: text under 12px`).toEqual([])
}

for (const size of SIZES) {
  test.describe(`drawer text layout (${size.name})`, () => {
    test.beforeEach(async ({ page }) => {
      await page.setViewportSize({ width: size.width, height: size.height })
    })

    test('asset drawer, every tab', async ({ page }, info) => {
      const sheet = await openFirstAssetSheet(page)
      test.skip(!sheet, 'No assets in tenant')
      const tabs = sheet!.getByRole('tab')
      const count = await tabs.count()
      for (let i = 0; i < count; i++) {
        const tab = tabs.nth(i)
        const name = ((await tab.innerText()) || `tab-${i}`).trim().split('\n')[0]
        await tab.click()
        await page.waitForLoadState('networkidle')
        await shot(page, info, `${size.name}-asset-${name}`)
        await check(sheet!, `asset drawer, ${name} tab`)
      }
    })

    test('finding drawer', async ({ page }, info) => {
      await page.goto('/findings')
      const row = await firstDataRow(page)
      test.skip(!row, 'No findings in tenant')
      await row!.click()
      const sheet = page.getByRole('dialog')
      await expect(sheet).toBeVisible({ timeout: 15_000 })
      await page.waitForLoadState('networkidle')
      await shot(page, info, `${size.name}-finding`)
      await check(sheet, 'finding drawer')
      const tabs = sheet.getByRole('tab')
      const count = await tabs.count()
      for (let i = 0; i < count; i++) {
        const name = ((await tabs.nth(i).innerText()) || `tab-${i}`).trim().split('\n')[0]
        await tabs.nth(i).click()
        await page.waitForLoadState('networkidle')
        await shot(page, info, `${size.name}-finding-${name}`)
        await check(sheet, `finding drawer, ${name} tab`)
      }
    })

    test('scan run view', async ({ page }, info) => {
      test.setTimeout(120_000)
      const list = page.waitForResponse(
        (r) => new URL(r.url()).pathname === '/api/v1/scans' && r.ok(),
        { timeout: 60_000 }
      )
      await page.goto('/scans')
      const body = (await (await list).json()) as {
        data?: Array<{ id: string }>
        items?: Array<{ id: string }>
      }
      const scans = body.data ?? body.items ?? []
      test.skip(scans.length === 0, 'No scans in tenant')
      await page.goto(`/scans/${scans[0].id}`)
      const runs = page.getByRole('tab', { name: /runs/i })
      if (await runs.isVisible().catch(() => false)) await runs.click()
      const row = await firstDataRow(page)
      test.skip(!row, 'The first scan has no runs')
      await row!.click()
      const sheet = page.getByRole('dialog')
      await expect(sheet).toBeVisible({ timeout: 15_000 })
      await page.waitForLoadState('networkidle')
      await shot(page, info, `${size.name}-scan-run`)
      await check(sheet, 'scan run view')
    })

    test('sensor drawer', async ({ page }, info) => {
      await page.goto('/sensors')
      const first = page.locator('[data-slot="sensor-name"]').first()
      const found = await first
        .waitFor({ timeout: 30_000 })
        .then(() => true)
        .catch(() => false)
      test.skip(!found, 'No sensor in the organization')
      await first.click()
      const sheet = page.locator('[data-slot="detail-sheet"]')
      await expect(sheet).toBeVisible()
      await page.waitForLoadState('networkidle')
      await shot(page, info, `${size.name}-sensor`)
      await check(sheet, 'sensor drawer')
      const tabs = sheet.getByRole('tab')
      const count = await tabs.count()
      for (let i = 0; i < count; i++) {
        const name = ((await tabs.nth(i).innerText()) || `tab-${i}`).trim().split('\n')[0]
        await tabs.nth(i).click()
        await page.waitForLoadState('networkidle')
        await shot(page, info, `${size.name}-sensor-${name}`)
        await check(sheet, `sensor drawer, ${name} tab`)
      }
    })
  })
}
