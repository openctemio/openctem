import { test, expect } from '../fixtures/authenticated-page'
import type { Page, TestInfo } from '@playwright/test'

/**
 * Dialog frame: a fixed header, a body that is the only part that scrolls, a
 * fixed footer (src/components/ui/modal-layout.tsx). The Add finding dialog is
 * the reference. On a phone its title, close button and Create button used to
 * scroll away with the fields.
 *
 * At a phone and a desktop size it checks that, with the body scrolled to the
 * end, the title has not moved, the close and Create buttons are inside the
 * viewport, and the dialog itself does not scroll. Screenshots are attached
 * to the report.
 */

const SIZES = [
  { name: 'phone', width: 390, height: 600 },
  { name: 'desktop', width: 1440, height: 900 },
]

async function openAddFinding(page: Page) {
  await page.goto('/findings')
  const add = page.getByRole('button', { name: 'Add finding' })
  await expect(add).toBeVisible({ timeout: 20_000 })
  await add.click()
  const dialog = page.getByRole('dialog', { name: /add finding/i })
  await expect(dialog).toBeVisible()
  return dialog
}

async function shot(page: Page, info: TestInfo, name: string) {
  await info.attach(name, { body: await page.screenshot(), contentType: 'image/png' })
}

for (const size of SIZES) {
  test(`Add finding keeps its header and actions in view (${size.name})`, async ({
    page,
  }, info) => {
    await page.setViewportSize({ width: size.width, height: size.height })
    const dialog = await openAddFinding(page)
    await expect(dialog).toHaveAttribute('data-layout', 'sections')

    const body = dialog.locator('[data-slot="dialog-body"]')
    const title = dialog.getByRole('heading', { name: /add finding/i })
    const close = dialog.getByRole('button', { name: 'Close' })
    const create = dialog.getByRole('button', { name: /create finding/i })

    const titleTop = (await title.boundingBox())!.y
    await shot(page, info, `${size.name}-top`)

    await body.evaluate((el) => {
      el.scrollTop = el.scrollHeight
    })
    await shot(page, info, `${size.name}-scrolled`)

    expect((await title.boundingBox())!.y).toBe(titleTop)
    await expect(close).toBeInViewport({ ratio: 1 })
    await expect(create).toBeInViewport({ ratio: 1 })
    // Only the body scrolls: the dialog itself has nothing to scroll.
    const dialogScrolls = await dialog.evaluate((el) => el.scrollHeight > el.clientHeight + 1)
    expect(dialogScrolls).toBe(false)

    await page.keyboard.press('Escape')
    await expect(dialog).toBeHidden()
  })
}
