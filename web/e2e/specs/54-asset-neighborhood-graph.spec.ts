import { test, expect } from '../fixtures/authenticated-page'
import type { Page } from '@playwright/test'

/**
 * The relationships graph of an asset (api docs/architecture/asset-relationships.md,
 * Neighborhood): an address shows the name that resolves to it AND the
 * domain that contains the name (its lineage up to the root), the name's
 * other addresses as one counted group that expands on demand. Each run uses
 * its own names under example.com and addresses from 198.18.0.0/15.
 */

type ApiResult = { status: number; body: string }

async function api(page: Page, method: string, path: string, data?: unknown): Promise<ApiResult> {
  return page.evaluate(
    async ({ method, path, data }) => {
      const r = await fetch(path, {
        method,
        headers: data === undefined ? {} : { 'Content-Type': 'application/json' },
        body: data === undefined ? undefined : JSON.stringify(data),
      })
      return { status: r.status, body: await r.text() }
    },
    { method, path, data }
  )
}

async function createAsset(page: Page, name: string, type: string): Promise<string> {
  const res = await api(page, 'POST', '/api/v1/assets', { name, type, criticality: 'low' })
  expect(res.status, `create ${name}: ${res.status} ${res.body}`).toBeLessThan(300)
  return (JSON.parse(res.body) as { id: string }).id
}

async function link(page: Page, source: string, target: string, type: string): Promise<number> {
  const res = await api(page, 'POST', `/api/v1/assets/${source}/relationships`, {
    type,
    source_asset_id: source,
    target_asset_id: target,
  })
  return res.status
}

test(
  'an address graph reaches the root domain and groups sibling addresses',
  { tag: ['@assets'] },
  async ({ page }) => {
    test.setTimeout(120_000)
    const stamp = Date.now().toString(36)
    const root = `nb-${stamp}.example.com`
    const mail = `mail.${root}`
    const octet = (Date.now() % 250) + 1
    const ips = [...Array(10)].map((_, i) => `198.18.${octet}.${i + 1}`)

    await page.goto('/assets')
    const rootId = await createAsset(page, root, 'domain')
    const mailId = await createAsset(page, mail, 'subdomain')
    const ipIds: string[] = []
    try {
      for (const ip of ips) ipIds.push(await createAsset(page, ip, 'ip_address'))
      const first = await link(page, rootId, mailId, 'contains')
      test.skip(first === 403 || first === 404, 'relationships module is off')
      expect(first === 409 || first < 300, `contains: ${first}`).toBe(true)
      for (const id of ipIds) {
        const s = await link(page, mailId, id, 'resolves_to')
        expect(s === 409 || s < 300, `resolves_to: ${s}`).toBe(true)
      }

      await page.goto(`/assets?q=${encodeURIComponent(ips[0])}`)
      const row = page.getByRole('row').filter({ hasText: ips[0] }).first()
      await expect(row).toBeVisible({ timeout: 30_000 })
      // A cell with no control opens the sheet (the name cell is a link).
      const cells = row.getByRole('cell')
      for (let i = 0; i < (await cells.count()); i++) {
        const cell = cells.nth(i)
        if ((await cell.locator('a, button, input, [role="checkbox"]').count()) === 0) {
          await cell.click()
          break
        }
      }
      const sheet = page.getByRole('dialog')
      await sheet.getByRole('tab', { name: /Relations/ }).click()
      await sheet.getByRole('button', { name: 'Graph' }).click()

      const canvas = sheet.getByRole('application', { name: 'Related assets graph' })
      await expect(canvas).toBeVisible({ timeout: 30_000 })
      // The root domain is drawn, two hops up, and named in the lineage trail.
      await expect(canvas.getByText(root, { exact: true })).toBeVisible()
      await expect(canvas.getByText(mail, { exact: true })).toBeVisible()
      const trail = sheet.getByRole('navigation', { name: 'Where this asset comes from' })
      await expect(trail.getByRole('button', { name: root, exact: true })).toBeVisible()
      // The nine other addresses of the name are one group, not nine nodes.
      const group = canvas.getByTestId('flow-node').filter({ hasText: '9 assets' })
      await expect(group).toBeVisible()
      await group.click()
      await sheet.getByRole('button', { name: 'Show all' }).click()
      await expect(canvas.getByText(ips[9], { exact: true })).toBeVisible()
      await expect(canvas.getByTestId('flow-node').filter({ hasText: '9 assets' })).toHaveCount(0)
    } finally {
      for (const id of [...ipIds, mailId, rootId]) await api(page, 'DELETE', `/api/v1/assets/${id}`)
    }
  }
)
