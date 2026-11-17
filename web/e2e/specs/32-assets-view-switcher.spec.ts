import { test, expect } from '../fixtures/authenticated-page'

/**
 * The list/category switcher on /assets sits at the far right of the title row,
 * in the same place in both views, on a phone and on desktop. On a phone the
 * list's primary action (Add asset) is a 36 px square in that row, before the
 * switcher, not a row of its own.
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
      if (width < 640) {
        await page.goto('/assets')
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
