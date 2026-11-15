import { chromium, expect, type Page } from '@playwright/test'
import { AUTH_DIR, credentials, STATE_FILE, answerCode, saveCredentials } from './helpers/session'
import fs from 'node:fs'

/**
 * Opens the sign-in page. A navigation of the page's own (the console's full
 * reload after a sign-in or a password change, a server that has only just
 * started answering) can abort this one: Chromium reports net::ERR_ABORTED, or
 * "interrupted by another navigation" when the page is itself going to /login.
 * It is retried, a bounded number of times, for those two answers only; any
 * other failure throws.
 */
async function openLogin(page: Page) {
  for (let attempt = 1; ; attempt++) {
    try {
      await page.waitForLoadState('load', { timeout: 15_000 }).catch(() => undefined)
      await page.goto('/login', { waitUntil: 'domcontentloaded' })
      return
    } catch (err) {
      if (attempt >= 4 || !/net::ERR_ABORTED|interrupted by another navigation/.test(String(err)))
        throw err
      await page.waitForTimeout(500 * attempt)
    }
  }
}

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
      await openLogin(page)
      // The form is server-rendered, then hydrated: text typed before React
      // has taken the inputs over is lost, and typing the same text again is
      // ignored (React compares it with the value it saw), so Continue stays
      // disabled for good. Empty the fields first, then fill, until the button
      // is enabled: that is the proof the page is live.
      const next = page.getByRole('button', { name: 'Continue' })
      const emailField = page.getByLabel('Email')
      const passwordField = page.getByLabel('Password', { exact: true })
      await expect(async () => {
        await emailField.fill('')
        await passwordField.fill('')
        await emailField.fill(email)
        await passwordField.fill(pw)
        await expect(next).toBeEnabled({ timeout: 1_000 })
      }).toPass({ timeout: 30_000 })
      await next.click()
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
    // The picture is a courtesy: when the page is closed or mid-navigation the
    // capture itself fails, and that failure must never replace the real error.
    const failed = browser.contexts()[0]?.pages()[0]
    if (failed && !failed.isClosed()) {
      await failed
        .screenshot({ path: `${AUTH_DIR}/setup-failed.png`, timeout: 5_000 })
        .catch(() => undefined)
    }
    throw err
  } finally {
    await browser.close()
  }
}
