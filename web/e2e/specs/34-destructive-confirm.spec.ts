import { test, expect } from '../fixtures/authenticated-page'

/**
 * Deleting something that cannot be undone asks for its name (research/213
 * tier T2), on a phone and on a desktop:
 * - the confirm button stays disabled until the exact name is typed;
 * - Enter in the field never fires the delete;
 * - the field does not autocapitalise (phone keyboards would break the match);
 * - the dialog fits the screen.
 *
 * Uses the seeded asset 10.20.30.40 and never confirms, so nothing changes.
 * The phone list has no row menu, so the dialog is opened at desktop width
 * and checked after the window shrinks to the phone width.
 */

const ASSET = '10.20.30.40'

for (const width of [390, 1440]) {
  test(
    `asset delete asks for the name and Enter does nothing (${width}px)`,
    { tag: ['@assets', '@shell'] },
    async ({ page }) => {
      await page.setViewportSize({ width: 1440, height: 900 })
      await page.goto('/assets')
      const actions = page.getByRole('button', { name: `Actions for ${ASSET}` })
      await expect(actions).toBeVisible({ timeout: 30_000 })
      await actions.click()
      await page.getByRole('menuitem', { name: 'Delete', exact: true }).click()

      await page.setViewportSize({ width, height: width < 640 ? 844 : 900 })
      const dialog = page.getByRole('alertdialog')
      await expect(dialog).toBeVisible()
      await expect(dialog).toContainText(ASSET)
      const confirm = dialog.getByRole('button', { name: 'Delete', exact: true })
      await expect(confirm).toBeDisabled()

      const field = dialog.getByRole('textbox')
      await expect(field).toHaveAttribute('autocapitalize', 'none')
      await expect(field).toBeFocused()
      await field.fill(ASSET.slice(0, -1))
      await field.press('Enter')
      await expect(dialog).toBeVisible()
      await expect(confirm).toBeDisabled()

      await field.fill(` ${ASSET} `) // a paste with spaces still matches
      await expect(confirm).toBeEnabled()
      await field.press('Enter')
      await expect(dialog).toBeVisible() // Enter never confirms

      const box = await dialog.boundingBox()
      expect(box, 'dialog box').not.toBeNull()
      expect(box!.x).toBeGreaterThanOrEqual(0)
      expect(box!.x + box!.width).toBeLessThanOrEqual(width)

      await dialog.getByRole('button', { name: 'Cancel' }).click()
      await expect(dialog).toBeHidden()
      await page.setViewportSize({ width: 1440, height: 900 })
      await expect(page.getByRole('button', { name: `Actions for ${ASSET}` })).toBeVisible()
    }
  )
}
