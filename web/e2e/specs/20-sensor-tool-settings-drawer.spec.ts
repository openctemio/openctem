import { test, expect } from '../fixtures/authenticated-page'
import type { Page, TestInfo } from '@playwright/test'

/**
 * Sensor drawer, Tool settings tab: expanding a tool on a phone used to
 * scroll the drawer frame itself (overflow hidden, scrollable by script)
 * through `scrollIntoView`, which left a blank band under the body and cut
 * the expanded tool off with no way to scroll to the rest.
 *
 * At a phone and a desktop size it opens the first sensor's Tool settings,
 * expands the first tool and checks that the drawer frame has not scrolled,
 * that the body reaches the bottom of the frame, and that the body can be
 * scrolled to the end of the expanded tool. Skips when the organization has
 * no sensor whose tools declare settings.
 */

const SIZES = [
  { name: 'phone', width: 390, height: 844 },
  { name: 'desktop', width: 1280, height: 900 },
]

async function shot(page: Page, info: TestInfo, name: string) {
  await info.attach(name, { body: await page.screenshot(), contentType: 'image/png' })
}

for (const size of SIZES) {
  test(`expanded tool settings stay fully reachable (${size.name})`, async ({ page }, info) => {
    // The first sensor's name, read from the table (a phone shows cards).
    await page.setViewportSize({ width: 1280, height: 900 })
    await page.goto('/sensors')
    const first = page.locator('[data-slot="sensor-name"]').first()
    const found = await first
      .waitFor({ timeout: 30_000 })
      .then(() => true)
      .catch(() => false)
    test.skip(!found, 'no sensor in the organization')
    const name = (await first.innerText()).trim()
    await page.setViewportSize({ width: size.width, height: size.height })
    await page.reload()
    await page.getByText(name, { exact: true }).first().click()
    const sheet = page.locator('[data-slot="detail-sheet"]')
    await expect(sheet).toBeVisible()
    const tab = sheet.getByRole('tab', { name: /tool settings/i })
    test.skip(!(await tab.isVisible()), 'no Tool settings tab (needs sensors:write)')
    await tab.click()
    const tool = sheet.locator('[data-tool]').first()
    const hasTool = await tool
      .waitFor({ timeout: 15_000 })
      .then(() => true)
      .catch(() => false)
    test.skip(!hasTool, 'no tool on this sensor declares settings')
    await tool.getByRole('button').first().click()
    const content = tool.locator('[data-slot="accordion-content"]').first()
    await expect(content).toBeVisible()
    await content.evaluate((el) => Promise.all(el.getAnimations().map((a) => a.finished)))
    await page.waitForTimeout(300)
    await shot(page, info, `${size.name}-expanded`)

    // The frame never scrolls: only its body does.
    expect(await sheet.evaluate((el) => el.scrollTop)).toBe(0)

    // The body reaches the bottom of the frame (no blank band under it).
    const frameBox = (await sheet.boundingBox())!
    const body = sheet.locator('.overflow-y-auto').first()
    const bodyBox = (await body.boundingBox())!
    expect(frameBox.y + frameBox.height - (bodyBox.y + bodyBox.height)).toBeLessThan(64)

    // Scrolled to the end, the end of the expanded tool is inside the body.
    await body.evaluate((el) => {
      el.scrollTop = el.scrollHeight
    })
    await shot(page, info, `${size.name}-scrolled`)
    const end = (await content.boundingBox())!
    const bodyAfter = (await body.boundingBox())!
    expect(end.y + end.height).toBeLessThanOrEqual(bodyAfter.y + bodyAfter.height + 1)
  })
}
