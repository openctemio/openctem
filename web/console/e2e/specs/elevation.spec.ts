import { test, expect, type Page } from '@playwright/test'
import { STATE_FILE, credentials } from '../helpers/session'
import { freshTotp } from '../helpers/totp'

/**
 * The elevation flow: a signed-in administrator is read-only, elevates with a
 * reason and an authenticator code, and a protected page then renders its
 * content. The checks read the session through the console's own API, so the
 * flow keeps passing while the dialog and the chip change their look.
 */

test.use({ storageState: STATE_FILE })

interface Identity {
  csrf_token?: string
  elevated_as?: string
}

async function identity(page: Page): Promise<Identity> {
  return page.evaluate(async () => {
    const res = await fetch('/api/v1/admin/auth/validate', { credentials: 'same-origin' })
    return (await res.json()) as Identity
  })
}

async function endElevation(page: Page) {
  const s = await identity(page)
  await page.evaluate(async (csrf) => {
    await fetch('/api/v1/admin/auth/elevate', {
      method: 'DELETE',
      credentials: 'same-origin',
      headers: { 'X-CSRF-Token': csrf ?? '' },
    })
  }, s.csrf_token)
}

test('read-only, elevate with a code, then a protected page renders', async ({ page }) => {
  await page.goto('/')
  await endElevation(page)
  await page.reload()
  expect((await identity(page)).elevated_as, 'the session is read-only').toBeUndefined()

  // Read-only: a protected page asks for the elevation instead of its content.
  await page.goto('/security/administrators')
  await expect(page.getByRole('button', { name: /^Elevate/ }).first()).toBeVisible()
  await expect(page.getByRole('table')).toHaveCount(0)

  await page
    .getByRole('button', { name: /^Elevate/ })
    .first()
    .click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Reason').fill('console e2e elevation flow')
  await dialog.getByRole('button', { name: /^Elevate/ }).click()

  // The authenticator code: asked in this dialog or the step-up one that follows.
  const code = page.locator('input[autocomplete="one-time-code"]').first()
  await code.waitFor({ timeout: 15_000 })
  await code.fill(await freshTotp(credentials().totpSecret))
  await page.keyboard.press('Enter')

  await expect
    .poll(async () => (await identity(page)).elevated_as, { timeout: 20_000 })
    .toBeTruthy()

  await page.goto('/security/administrators')
  await expect(page.locator('main h1').first()).toBeVisible()
  await expect(page.getByRole('table').first()).toBeVisible({ timeout: 20_000 })
})
