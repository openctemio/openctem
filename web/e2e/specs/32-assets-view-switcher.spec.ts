import { test, expect } from '../fixtures/authenticated-page'

/**
 * The list/category switcher on /assets sits at the far right of the title row,
 * in the same place in both views, on a phone and on desktop. On a phone the
 * list's primary action (Add asset) is a 36 px square in that row, before the
 * switcher, not a row of its own, and Export is an item of the list's More.
 */
for (const width of [390, 1440]) {
  test(
    `assets view switcher is in the same place in both views at ${width}px`,
    { tag: ['@assets'] },
    async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 900 })
      const boxes = []
      for (const view of ['list', 'categories']) {
        await page.goto(view === 'list' ? '/assets' : '/assets?view=categories')
        const switcher = page.getByRole('group', { name: 'View' })
        await expect(switcher).toBeVisible({ timeout: 30_000 })
        const title = await page.getByRole('heading', { level: 1, name: 'Assets' }).boundingBox()
        const box = await switcher.boundingBox()
        expect(box && title).toBeTruthy()
        // Same row as the title, at the right edge, at the row's control
        // height ("Sizes" in docs/ui-style-contract.md): 32, 36 below 768px.
        expect(Math.abs(box!.y - title!.y)).toBeLessThan(16)
        expect(Math.abs(box!.height - (width < 768 ? 36 : 32))).toBeLessThanOrEqual(0.5)
        expect(box!.x + box!.width).toBeGreaterThan(width - 80)
        boxes.push(box!)
        await testInfo.attach(`assets-${view}-${width}.png`, {
          body: await page.screenshot(),
          contentType: 'image/png',
        })
      }
      expect(Math.abs(boxes[0].x - boxes[1].x)).toBeLessThan(2)
      expect(Math.abs(boxes[0].y - boxes[1].y)).toBeLessThan(2)
      await page.goto('/assets')
      // Export: a button of the list's title row from 768 px; on a phone an
      // item of the More menu that ends the toolbar (a control never stands
      // alone on the phone title row), so the row keeps the view's name and state.
      const titleRow = page.getByTestId('inventory-title-row')
      await expect(titleRow).toBeVisible({ timeout: 30_000 })
      const exportButton = titleRow.getByRole('button', { name: /^export/i })
      if (width < 768) {
        await expect(exportButton).toHaveCount(0)
        await expect(titleRow.getByRole('button', { name: 'More actions' })).toHaveCount(0)
        await page
          .locator('[data-slot="list-toolbar-region"], [data-testid="data-table-toolbar"]')
          .first()
          .getByRole('button', { name: 'More actions' })
          .click()
        // A menu, or a bottom sheet when the menu does not fit.
        const item = page
          .getByRole('menuitem', { name: 'Export' })
          .or(page.getByRole('dialog').getByRole('button', { name: 'Export' }))
        await expect(item).toBeVisible()
        await page.keyboard.press('Escape')
        await expect(item).toHaveCount(0)
      } else {
        await expect(exportButton).toBeVisible()
      }
      if (width < 640) {
        const add = page.locator('main [data-slot="page-header"]').getByRole('button', {
          name: /^add /i,
        })
        await expect(add).toBeVisible({ timeout: 30_000 })
        const addBox = (await add.boundingBox())!
        // In the title's row, a square, left of the switcher.
        expect(Math.abs(addBox.y - boxes[0].y)).toBeLessThan(2)
        expect(Math.abs(addBox.width - 36)).toBeLessThanOrEqual(0.5)
        expect(Math.abs(addBox.height - 36)).toBeLessThanOrEqual(0.5)
        expect(addBox.x + addBox.width).toBeLessThanOrEqual(boxes[0].x)
      }
    }
  )
}
