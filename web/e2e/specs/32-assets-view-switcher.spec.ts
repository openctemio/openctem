import { test, expect } from '../fixtures/authenticated-page'

/**
 * The list/category switcher on /assets sits at the far right of the title row,
 * in the same place in both views, on a phone and on desktop. On a phone the
 * page actions wrap to their own row under the title instead of beside it.
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
        // Same row as the title, at the right edge, at least 36px tall.
        expect(Math.abs(box!.y - title!.y)).toBeLessThan(16)
        expect(box!.height).toBeGreaterThanOrEqual(35.5)
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
        const add = page.getByRole('button', { name: /export/i })
        await page.goto('/assets')
        const exportBox = await add.boundingBox()
        if (exportBox) expect(exportBox.y).toBeGreaterThan(boxes[0].y + boxes[0].height - 1)
      }
    }
  )
}
