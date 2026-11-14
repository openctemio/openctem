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
      // The card names the group's first members at once, the rest counted.
      const members = sheet.getByRole('list', { name: 'Assets in this group' })
      await expect(members.getByRole('button')).toHaveCount(5)
      await expect(sheet.getByText('and 4 more')).toBeVisible()
      await sheet.getByRole('button', { name: 'Show all' }).click()
      await expect(canvas.getByText(ips[9], { exact: true })).toBeVisible()
      await expect(canvas.getByTestId('flow-node').filter({ hasText: '9 assets' })).toHaveCount(0)

      // Full screen: the same graph (expanded group included) in a
      // full-viewport dialog, with the hops selector; f and Escape.
      await sheet.getByRole('button', { name: '3', exact: true }).click()
      await canvas.getByTestId('flow-fullscreen-toggle').click()
      const full = page.getByRole('dialog', { name: `Related assets of ${ips[0]}` })
      await expect(full).toBeVisible()
      const fullCanvas = full.getByRole('application', { name: 'Related assets graph' })
      await expect(fullCanvas.getByText(root, { exact: true })).toBeVisible()
      await expect(full.getByRole('button', { name: '3', exact: true })).toHaveAttribute(
        'aria-pressed',
        'true'
      )
      // The dialog opens with a zoom-in animation, and boundingBox reports the
      // transformed box: poll until it has settled at the full viewport.
      const vp = page.viewportSize()
      await expect
        .poll(
          async () => {
            const box = await full.boundingBox()
            return !!(box && vp && box.width >= vp.width - 2 && box.height >= vp.height - 2)
          },
          { message: 'the full-screen graph fills the viewport once it has opened' }
        )
        .toBe(true)
      await page.keyboard.press('Escape')
      await expect(full).toBeHidden()
      await expect(canvas).toBeVisible()
      await canvas.getByTestId('flow-node').first().focus()
      await page.keyboard.press('f')
      await expect(full).toBeVisible()
      await page.keyboard.press('f')
      await expect(full).toBeHidden()
    } finally {
      for (const id of [...ipIds, mailId, rootId]) await api(page, 'DELETE', `/api/v1/assets/${id}`)
    }
  }
)

type Box = { x: number; y: number; width: number; height: number }
const overlaps = (a: Box, b: Box) =>
  a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height

test.describe('on a phone', () => {
  test(
    'a group of 22 names its members and the controls cover no node',
    { tag: ['@assets'] },
    async ({ page }) => {
      test.setTimeout(180_000)
      const stamp = Date.now().toString(36)
      const name = `nbp-${stamp}.example.com`
      const octet = (Date.now() % 250) + 1
      const ips = [...Array(23)].map((_, i) => `198.19.${octet}.${i + 1}`)

      await page.goto('/assets')
      const nameId = await createAsset(page, name, 'subdomain')
      const ipIds: string[] = []
      try {
        for (const ip of ips) ipIds.push(await createAsset(page, ip, 'ip_address'))
        const first = await link(page, nameId, ipIds[0], 'resolves_to')
        test.skip(first === 403 || first === 404, 'relationships module is off')
        for (const id of ipIds.slice(1)) {
          const s = await link(page, nameId, id, 'resolves_to')
          expect(s === 409 || s < 300, `resolves_to: ${s}`).toBe(true)
        }

        await page.goto(`/assets?q=${encodeURIComponent(ips[0])}`)
        const row = page.getByRole('row').filter({ hasText: ips[0] }).first()
        await expect(row).toBeVisible({ timeout: 30_000 })
        const cells = row.getByRole('cell')
        for (let i = 0; i < (await cells.count()); i++) {
          const cell = cells.nth(i)
          if ((await cell.locator('a, button, input, [role="checkbox"]').count()) === 0) {
            await cell.click()
            break
          }
        }
        // The inventory opens the sheet from a table row; the panel is then
        // checked at phone width.
        await page.setViewportSize({ width: 390, height: 844 })
        const sheet = page.getByRole('dialog')
        await sheet.getByRole('tab', { name: /Relations/ }).click()
        await sheet.getByRole('button', { name: 'Graph' }).click()
        const canvas = sheet.getByRole('application', { name: 'Related assets graph' })
        await expect(canvas.getByText(name, { exact: true })).toBeVisible({ timeout: 30_000 })

        // No zoom or full-screen control covers a node of the fitted view.
        await page.waitForTimeout(500)
        const controls = [
          canvas.getByRole('button', { name: 'Zoom in' }),
          canvas.getByRole('button', { name: 'Zoom out' }),
          canvas.getByRole('button', { name: 'Fit view' }),
          canvas.getByTestId('flow-fullscreen-toggle'),
        ]
        const nodes = canvas.getByTestId('flow-node')
        for (let i = 0; i < (await nodes.count()); i++) {
          const nb = await nodes.nth(i).boundingBox()
          for (const c of controls) {
            const cb = await c.boundingBox()
            if (nb && cb) expect(overlaps(nb, cb), `control over node ${i}`).toBe(false)
          }
        }

        const group = canvas.getByTestId('flow-node').filter({ hasText: '22 assets' })
        await group.click()
        const members = sheet.getByRole('list', { name: 'Assets in this group' })
        const rows = members.getByRole('button')
        await expect(rows).toHaveCount(5)
        await expect(sheet.getByText('and 17 more')).toBeVisible()
        for (let i = 0; i < 5; i++) {
          const b = await rows.nth(i).boundingBox()
          expect(b && b.height >= 44, `row ${i} touch target`).toBe(true)
          expect(b && b.x >= 0 && b.x + b.width <= 390, `row ${i} inside the screen`).toBe(true)
        }
        expect(
          await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)
        ).toBe(true)

        // A member opens its asset; Show all draws the whole group.
        const firstName = (await rows.first().innerText()).split('\n')[0]
        expect(ips).toContain(firstName)
        await sheet.getByRole('button', { name: 'Show all' }).click()
        await expect(canvas.getByTestId('flow-node').filter({ hasText: '22 assets' })).toHaveCount(
          0
        )
        await expect(canvas.getByText(ips[22], { exact: true })).toBeAttached()
      } finally {
        for (const id of [...ipIds, nameId]) await api(page, 'DELETE', `/api/v1/assets/${id}`)
      }
    }
  )
})
