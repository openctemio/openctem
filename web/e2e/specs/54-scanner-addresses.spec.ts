import type { Page } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'

/**
 * Settings, Scanning, Proxies: the "Scanner addresses" card at 390px and
 * 1440px. The list is answered with one address of each kind (a proxy exit,
 * a sensor, a published shared-sensor range), so the spec does not depend on
 * a proxy test having run. Checks: every address and its source shows, the
 * allowlist switches format, long addresses wrap inside the card, the card
 * is the target of #scanner-addresses, and the page never scrolls sideways.
 */

const addresses = {
  items: [
    {
      address: '2001:db8:ffff:ffff:ffff:ffff:ffff:fff1',
      cidr: '2001:db8:ffff:ffff:ffff:ffff:ffff:fff1/128',
      kind: 'proxy_exit',
      private: false,
      pool_id: '00000000-0000-4000-8000-0000000000c1',
      pool_name: 'e2e-egress',
      endpoint_id: '00000000-0000-4000-8000-0000000000c2',
      endpoint_label: 'dc1',
      last_seen_at: new Date().toISOString(),
    },
    {
      address: '10.20.30.40',
      cidr: '10.20.30.40/32',
      kind: 'sensor',
      private: true,
      sensor_id: '00000000-0000-4000-8000-0000000000c3',
      sensor_name: 'e2e-sensor',
    },
    { address: '192.0.2.0/24', cidr: '192.0.2.0/24', kind: 'platform', private: false },
  ],
  cidrs: ['10.20.30.40/32', '192.0.2.0/24', '2001:db8:ffff:ffff:ffff:ffff:ffff:fff1/128'],
}

async function openProxies(page: Page) {
  await page.route(
    (url) => url.pathname === '/api/v1/proxy-pools/scanner-addresses',
    (route) => route.fulfill({ json: addresses })
  )
  await page.goto('/settings/scanning/proxies#scanner-addresses')
  await expect(page.getByTestId('scanner-addresses-card')).toBeVisible({ timeout: 45_000 })
}

for (const width of [390, 1440] as const) {
  test(
    `scanner addresses card at ${width}px: addresses, sources and allowlist fit`,
    { tag: ['@sensors'] },
    async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: width === 390 ? 844 : 900 })
      await openProxies(page)
      const card = page.getByTestId('scanner-addresses-card')
      await card.scrollIntoViewIfNeeded()
      await testInfo.attach(`scanner-addresses-${width}`, {
        body: await card.screenshot(),
        contentType: 'image/png',
      })

      await expect(card.getByText('Pool e2e-egress, proxy dc1')).toBeVisible()
      await expect(card.getByText('Sensor e2e-sensor, scanning without a proxy')).toBeVisible()
      await expect(card.getByText('Shared sensors of this platform')).toBeVisible()
      const snippet = page.getByTestId('scanner-addresses-snippet')
      await expect(snippet).toHaveText(addresses.cidrs.join('\n'))
      await card.getByRole('tab', { name: '"Require ip" rule' }).click()
      await expect(snippet).toHaveText(`Require ip ${addresses.cidrs.join(' ')}`)

      const defects = await page.evaluate(() => {
        const out: string[] = []
        const doc = document.documentElement
        if (doc.scrollWidth > doc.clientWidth) {
          out.push(`page scrolls sideways by ${doc.scrollWidth - doc.clientWidth}px`)
        }
        const card = document.querySelector('[data-testid="scanner-addresses-card"]')!
        const cb = card.getBoundingClientRect()
        for (const e of Array.from(card.querySelectorAll('*'))) {
          const b = e.getBoundingClientRect()
          if (b.width > 0 && (b.right > cb.right + 0.5 || b.left < cb.left - 0.5)) {
            out.push(`"${(e.textContent ?? '').trim().slice(0, 40)}" runs out of the card`)
            break
          }
        }
        return out
      })
      expect(defects).toEqual([])
    }
  )
}
