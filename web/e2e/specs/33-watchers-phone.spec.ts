import { test, expect } from '../fixtures/authenticated-page'

/**
 * Watchers on a phone (390px), finding detail page (research/256).
 *
 * Regression guarded: each watcher row had a small × next to the name that
 * removed the person on one tap, easy to hit while scrolling. Now:
 *   1. the rail has no control that removes anyone: one summary row
 *      ("N watching") and your own Watch toggle, both at least 44px tall;
 *   2. removing needs the Manage watchers sheet, behind a labelled Remove
 *      button (44px), and the toast offers Undo, which puts the person back;
 *   3. your own row in the sheet says Stop watching, never Remove;
 *   4. the People heading is sentence case.
 */

/** 44px touch target, with room for sub-pixel layout rounding. */
const TOUCH = 43.5

type ListedFinding = { id: string }

async function firstFinding(page: import('@playwright/test').Page): Promise<string | undefined> {
  const res = page.waitForResponse((r) => /\/api\/v1\/findings\?/.test(r.url()) && r.ok(), {
    timeout: 60_000,
  })
  await page.goto('/findings')
  const body = (await (await res).json()) as { data?: ListedFinding[] }
  return body.data?.[0]?.id
}

test('watchers at 390px: no one-tap removal, manage sheet with undo', async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const id = await firstFinding(page)
  test.skip(!id, 'Needs a finding')

  await page.goto(`/findings/${id}`)
  const people = page.getByRole('group', { name: 'People' })
  await expect(people).toBeVisible({ timeout: 45_000 })
  const summary = people.getByTestId('watchers-summary')
  await expect(summary).toBeVisible({ timeout: 30_000 })
  await summary.scrollIntoViewIfNeeded()

  // 4. Sentence case heading.
  const transform = await people
    .getByText('People', { exact: true })
    .evaluate((el) => getComputedStyle(el).textTransform)
  expect(transform).toBe('none')

  // 1. Nothing in the rail removes anyone; the two controls are touch-sized.
  await expect(people.getByRole('button', { name: /^Remove/ })).toHaveCount(0)
  const toggle = people.getByTestId('watch-toggle')
  for (const l of [summary, toggle]) {
    const box = await l.boundingBox()
    expect(box && box.height, 'touch target').toBeGreaterThanOrEqual(TOUCH)
  }
  await testInfo.attach('watchers-rail-390.png', {
    body: await people.screenshot(),
    contentType: 'image/png',
  })

  // Make sure we are watching, so our own row is in the sheet.
  if ((await toggle.textContent())?.trim() === 'Watch') {
    await toggle.click()
    await expect(toggle).toHaveText('Watching')
  }

  // 2 and 3. The sheet.
  await summary.click()
  const sheet = page.getByRole('dialog', { name: /^Watchers/ })
  await expect(sheet).toBeVisible()
  await expect(sheet.getByRole('button', { name: 'Stop watching' })).toBeVisible()

  const removes = sheet.getByRole('button', { name: /^Remove / })
  const n = await removes.count()
  if (n > 0) {
    const first = removes.first()
    const box = await first.boundingBox()
    expect(box && box.height, 'Remove touch target').toBeGreaterThanOrEqual(TOUCH)
    const name = ((await first.getAttribute('aria-label')) ?? '').replace(/^Remove /, '')
    await testInfo.attach('watchers-sheet-390.png', {
      body: await page.screenshot(),
      contentType: 'image/png',
    })

    await first.click()
    await expect(sheet.getByRole('button', { name: `Remove ${name}` })).toHaveCount(0)
    const toast = page.locator('[data-sonner-toast]').filter({ hasText: name })
    await expect(toast).toBeVisible()
    await testInfo.attach('watchers-undo-390.png', {
      body: await page.screenshot(),
      contentType: 'image/png',
    })
    // Undo stays clickable over the open sheet and puts the person back.
    await toast.getByRole('button', { name: 'Undo' }).click()
    await expect(sheet.getByRole('button', { name: `Remove ${name}` })).toBeVisible()
  }

  await sheet.getByRole('button', { name: 'Done' }).click()
  await expect(sheet).toBeHidden()
  await expect(summary).toBeFocused()
})
