import { test, expect } from '../fixtures/authenticated-page'
import type { Page } from '@playwright/test'

/**
 * How this asset was found (api docs/architecture/easm.md, Discovery lineage):
 * a subdomain under a domain shows the chain root first, the domain as a
 * link, at desktop and phone width without sideways scroll. Each run uses
 * its own names under example.com.
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

test('the asset page shows how a subdomain was found', { tag: ['@assets'] }, async ({ page }) => {
  test.setTimeout(90_000)
  const stamp = Date.now().toString(36)
  const root = `lin-${stamp}.example.com`
  const child = `app.${root}`

  await page.goto('/assets')
  const rootId = await createAsset(page, root, 'domain')
  const childId = await createAsset(page, child, 'subdomain')
  try {
    const rel = await api(page, 'POST', `/api/v1/assets/${rootId}/relationships`, {
      type: 'contains',
      source_asset_id: rootId,
      target_asset_id: childId,
    })
    // 409: the platform already linked the name to its domain.
    test.skip(rel.status === 403 || rel.status === 404, 'relationships module is off')
    expect(rel.status === 409 || rel.status < 300, `link: ${rel.status} ${rel.body}`).toBe(true)

    for (const viewport of [
      { width: 1280, height: 900 },
      { width: 390, height: 844 },
    ]) {
      await page.setViewportSize(viewport)
      await page.goto(`/assets/${childId}`)
      const section = page.getByRole('region', { name: 'How this asset was found' })
      await expect(section).toBeVisible({ timeout: 30_000 })
      const chain = section.getByRole('list', { name: 'Discovery chain' })
      await expect(chain.getByRole('link', { name: root })).toHaveAttribute(
        'href',
        `/assets/${rootId}`
      )
      await expect(chain.getByText('This asset')).toBeVisible()
      await section.scrollIntoViewIfNeeded()
      const sideways = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth
      )
      expect(sideways, `page scrolls sideways at ${viewport.width}px`).toBeLessThanOrEqual(0)
    }
  } finally {
    await api(page, 'DELETE', `/api/v1/assets/${childId}`)
    await api(page, 'DELETE', `/api/v1/assets/${rootId}`)
  }
})
