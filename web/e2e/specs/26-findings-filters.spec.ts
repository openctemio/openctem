import { test, expect } from '../fixtures/authenticated-page'

/**
 * Findings filters: every active filter is a chip, Add filter is built from the
 * API's filter contract (searchable, grouped, typed), an unknown filter in a
 * shared link is named and removable, and a filter the page does not draw
 * itself still reaches the API. Needs no particular data.
 */

test.describe('Findings filters', { tag: ['@findings'] }, () => {
  test('Add filter lists the contract fields, searches them and adds a chip and a URL param', async ({
    page,
  }) => {
    await page.goto('/findings')
    await page.getByRole('button', { name: /add filter/i }).click()
    const dialog = page.getByRole('dialog', { name: /add filter/i })
    await expect(dialog.getByRole('option', { name: 'Severity' })).toBeVisible({ timeout: 20_000 })
    for (const group of ['Exploitation', 'Finding']) {
      await expect(dialog.getByText(group, { exact: true })).toBeVisible()
    }
    await dialog.getByPlaceholder(/search fields/i).fill('epss')
    await expect(dialog.getByRole('option', { name: 'Severity' })).toHaveCount(0)
    await dialog.getByRole('option', { name: /epss score/i }).click()
    await dialog.getByLabel('Value').fill('0.5')
    await dialog.getByRole('button', { name: 'Apply' }).click()
    await expect(page).toHaveURL(/epss_score_gte=0\.5/)
    await expect(
      page.getByTestId('filter-chip').filter({ hasText: 'EPSS score ≥ 0.5' })
    ).toBeVisible()
  })

  test('Query mode shows the whole filter as server text and writes it back losslessly', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings?severity=critical')
    await page.getByRole('button', { name: /^query$/i }).click()
    const box = page.getByRole('combobox', { name: /filter as query text/i })
    await expect(box).toBeEnabled({ timeout: 20_000 })
    // The State lens and the Practice switch are part of the printed filter.
    await expect(box).toHaveValue(/state=open/)
    await expect(box).toHaveValue(/practice!=compliance/)
    await expect(box).toHaveValue(/severity=critical/)
    // A refused text is never applied: one line with its column under the field.
    await box.fill('severity= AND kev=true')
    await box.press('Enter')
    await expect(box).toHaveAttribute('aria-invalid', 'true')
    await expect(page.getByText(/Column \d+\./)).toBeVisible()
    await expect(page).toHaveURL(/severity=critical/)
    // The suggestions stay closed so the problem line shows; Escape puts the
    // applied text back; Enter on a valid text applies it.
    await expect(box).toHaveAttribute('aria-expanded', 'false')
    await box.press('Escape')
    await expect(box).toHaveValue(/severity=critical/)
    await box.fill('kev=true')
    await box.press('Enter')
    await expect(page).toHaveURL(/is_in_kev=true/)
    await expect(page).toHaveURL(/state=all/)
    await expect(page).not.toHaveURL(/severity=critical/)
    await page.getByRole('button', { name: /^basic$/i }).click()
    await expect(page.getByTestId('filter-chip').first()).toBeVisible()
  })

  test('the f key opens Add filter, not while typing in search', async ({ page }) => {
    await page.goto('/findings')
    const search = page.getByRole('searchbox', { name: /search findings/i })
    await search.click()
    await page.keyboard.type('f')
    await expect(page.getByRole('dialog', { name: /add filter/i })).toHaveCount(0)
    await search.fill('')
    await page.locator('h1').click()
    await page.keyboard.press('f')
    await expect(page.getByRole('dialog', { name: /add filter/i })).toBeVisible()
  })

  test('a facet filter shows as a chip and removes from the URL', async ({ page }) => {
    await page.goto('/findings?severity=critical')
    const chip = page.getByTestId('filter-chip').filter({ hasText: 'Severity: Critical' })
    await expect(chip).toBeVisible({ timeout: 20_000 })
    await chip.getByRole('button', { name: /remove filter/i }).click()
    await expect(page).not.toHaveURL(/severity=/)
  })

  test("a chip's text opens its editor: the operator changes from the chip", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    const listRequests: string[] = []
    page.on('request', (r) => {
      const u = new URL(r.url())
      if (u.pathname === '/api/v1/findings') listRequests.push(u.search)
    })
    await page.goto('/findings')
    // Severity is Critical, through Add filter.
    await page.getByRole('button', { name: /add filter/i }).click()
    const picker = page.getByRole('dialog', { name: /add filter/i })
    await picker.getByRole('option', { name: 'Severity' }).click({ timeout: 20_000 })
    await picker.getByRole('checkbox', { name: 'Critical' }).check()
    await picker.getByRole('button', { name: 'Apply' }).click()
    await expect(page).toHaveURL(/[?&]severity=critical(&|$)/)
    const chip = page.getByTestId('filter-chip').filter({ hasText: 'Severity: Critical' })
    await expect(chip).toBeVisible()
    const count = page.locator('main [data-slot="list-count"]')
    await expect(count).toHaveText(/\d/, { timeout: 45_000 })
    const before = await count.innerText()
    const row = page.locator('main [data-slot="filter-chips-row"]:visible').first()
    const rowBox = await row.boundingBox()

    // The chip's text (not its X) opens the same editor, on "is" + Critical.
    await chip.locator('[data-slot="filter-chip-edit"]').click()
    const editor = page.getByRole('dialog', { name: 'Edit Severity filter' })
    await expect(editor.getByRole('checkbox', { name: 'Critical' })).toBeChecked({
      timeout: 20_000,
    })
    await expect(editor.getByRole('combobox', { name: 'Condition' })).toHaveText('is')

    // Escape changes nothing and returns focus to the chip.
    await page.keyboard.press('Escape')
    await expect(editor).toBeHidden()
    await expect(page).toHaveURL(/[?&]severity=critical(&|$)/)
    await expect(chip.locator('[data-slot="filter-chip-edit"]')).toBeFocused()

    // Enter opens it again; "is not" keeps Critical; Apply rewrites the filter.
    await page.keyboard.press('Enter')
    await editor.getByRole('combobox', { name: 'Condition' }).click()
    await page.getByRole('option', { name: 'is not' }).click()
    await expect(editor.getByRole('checkbox', { name: 'Critical' })).toBeChecked()
    await editor.getByRole('button', { name: 'Apply' }).click()
    await expect(page).toHaveURL(/[?&]severity_not=critical(&|$)/)
    await expect(page).not.toHaveURL(/[?&]severity=/)
    const edited = page.getByTestId('filter-chip').filter({ hasText: 'Severity is not Critical' })
    await expect(edited).toBeVisible()
    await expect(page.getByTestId('filter-chip')).toHaveCount(1)
    await expect(edited.locator('[data-slot="filter-chip-edit"]')).toBeFocused()
    await expect
      .poll(() => listRequests.some((q) => q.includes('severity_not=critical')))
      .toBe(true)
    // The other findings: the count is another number.
    await expect(count).not.toHaveText(before, { timeout: 45_000 })
    await expect(count).toHaveText(/\d/)
    // The chips row is still one line of the same height, in the same place.
    const after = await row.boundingBox()
    expect(after?.height).toBe(rowBox?.height)
    expect(after?.y).toBe(rowBox?.y)
  })

  test('an unknown filter and a locked chip have no editor', async ({ page }) => {
    await page.goto('/findings?sevrity=high&severity=low')
    await expect(page.getByTestId('filter-chip').first()).toBeVisible({ timeout: 20_000 })
    const unknown = page.getByTestId('filter-chip-unknown')
    if (await unknown.count()) {
      await expect(unknown.locator('[data-slot="filter-chip-edit"]')).toHaveCount(0)
    }
    await expect(
      page.locator('[data-testid="filter-chip"][data-locked="true"] [data-slot="filter-chip-edit"]')
    ).toHaveCount(0)
  })

  test('an unknown filter in a link is named, and removable', async ({ page }) => {
    await page.goto('/findings?sevrity=high')
    await expect(
      page.getByTestId('invalid-filter-notice').or(page.getByTestId('filter-chip-unknown'))
    ).toBeVisible({
      timeout: 20_000,
    })
    await expect(page.getByText(/sevrity/).first()).toBeVisible()
    const remove = page
      .getByRole('button', { name: /remove it/i })
      .or(page.getByRole('button', { name: /remove unknown filter/i }))
    await remove.first().click()
    await expect(page).not.toHaveURL(/sevrity=/)
  })

  test('a filter the page does not draw itself reaches the list request', async ({ page }) => {
    const seen: string[] = []
    page.on('request', (r) => {
      const u = new URL(r.url())
      if (u.pathname === '/api/v1/findings') seen.push(u.search)
    })
    await page.goto('/findings?epss_score_gte=0.5')
    await expect(page.getByTestId('filter-chip').filter({ hasText: 'EPSS score' })).toBeVisible({
      timeout: 20_000,
    })
    expect(seen.some((q) => q.includes('epss_score_gte=0.5'))).toBe(true)
  })

  test('a plain list does not ask for the filter contract', async ({ page }) => {
    const asked: string[] = []
    page.on('request', (r) => {
      if (r.url().includes('/api/v1/meta/filters/findings')) asked.push(r.url())
    })
    await page.goto('/findings?severity=high')
    await page.waitForLoadState('networkidle')
    expect(asked).toEqual([])
  })
})
