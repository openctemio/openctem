import { chromium } from '@playwright/test'
import { AUTH_DIR, credentials, STATE_FILE, answerCode, saveCredentials } from './helpers/session'
import fs from 'node:fs'

/**
 * Signs the platform administrator in once and saves the session. The sign-in
 * is the real one, through the console's pages: password, then the
 * authenticator step. An administrator who has never signed in is enrolled
 * first: the sign-in answer carries the authenticator secret, which is kept
 * (with the new password) for the specs that need a fresh code.
 *
 * CONSOLE_E2E_EMAIL, CONSOLE_E2E_PASSWORD (the temporary one is changed), and,
 * for an administrator who is already enrolled, CONSOLE_E2E_TOTP_SECRET.
 */
export default async function globalSetup() {
  const baseURL = process.env.CONSOLE_E2E_BASE_URL ?? 'http://127.0.0.1:3001'
  const email = process.env.CONSOLE_E2E_EMAIL
  const password = process.env.CONSOLE_E2E_PASSWORD
  if (!email || !password) {
    throw new Error(
      'set CONSOLE_E2E_EMAIL and CONSOLE_E2E_PASSWORD (see web/console/e2e/README.md)'
    )
  }
  fs.mkdirSync(AUTH_DIR, { recursive: true })
  const browser = await chromium.launch()
  try {
    const context = await browser.newContext({ baseURL })
    const page = await context.newPage()
    let secret = process.env.CONSOLE_E2E_TOTP_SECRET ?? ''
    if (process.env.CONSOLE_E2E_DEBUG) {
      page.on('response', (res) => {
        if (res.url().includes('/api/v1/admin/auth/')) console.log(res.status(), res.url())
      })
    }
    page.on('response', async (res) => {
      if (res.url().endsWith('/api/v1/admin/auth/login') && res.ok()) {
        const body = (await res.json().catch(() => ({}))) as { secret?: string }
        if (process.env.CONSOLE_E2E_DEBUG)
          console.log(Object.keys(body), String(body.secret).length)
        if (body.secret) secret = body.secret
      }
    })
    const signIn = async (pw: string) => {
      await page.goto('/login')
      await page.getByLabel('Email').fill(email)
      await page.getByLabel('Password', { exact: true }).fill(pw)
      await page.getByRole('button', { name: 'Continue' }).click()
      await answerCode(page, () => secret)
      // The sixth digit submits the step by itself.
      await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 60_000 })
    }
    // A run against a stack an earlier run already set up: the saved password and secret.
    let current = password
    try {
      const saved = credentials()
      if (saved.email === email) {
        current = saved.password
        secret = saved.totpSecret
      }
    } catch {
      // first run
    }
    await signIn(current)
    // A temporary password is changed before anything else: the console shows
    // only that form, and ends the session when it is done.
    const gate = page.locator('#pw-current')
    const gated = await gate.waitFor({ timeout: 15_000 }).then(
      () => true,
      () => false
    )
    if (gated) {
      current = `${password}-Changed1`
      await gate.fill(password)
      await page.locator('#pw-new').fill(current)
      await page.locator('#pw-confirm').fill(current)
      const changed = page.waitForResponse((r) => r.url().endsWith('/api/v1/admin/auth/password'))
      await page.getByRole('button', { name: 'Change password' }).click()
      const res = await changed
      if (!res.ok())
        throw new Error(`the password change answered ${res.status()}: ${await res.text()}`)
      await signIn(current)
    }
    saveCredentials({ email, password: current, totpSecret: secret })
    await context.storageState({ path: STATE_FILE })
  } catch (err) {
    await browser
      .contexts()[0]
      ?.pages()[0]
      ?.screenshot({ path: `${AUTH_DIR}/setup-failed.png` })
    throw err
  } finally {
    await browser.close()
  }
}
