import fs from 'node:fs'
import path from 'node:path'
import type { Browser, Page } from '@playwright/test'
import { freshTotp } from './totp'

export const AUTH_DIR = path.resolve(process.cwd(), '.console-e2e-auth')
export const STATE_FILE = path.join(AUTH_DIR, 'admin.json')
const CREDS_FILE = path.join(AUTH_DIR, 'credentials.json')

export interface Credentials {
  email: string
  password: string
  totpSecret: string
}

/** What the global setup learned: the changed password and the authenticator secret. */
export function credentials(): Credentials {
  return JSON.parse(fs.readFileSync(CREDS_FILE, 'utf8')) as Credentials
}

export function saveCredentials(c: Credentials) {
  fs.mkdirSync(AUTH_DIR, { recursive: true })
  fs.writeFileSync(CREDS_FILE, JSON.stringify(c), { mode: 0o600 })
}

/** Answers the authenticator step of the sign-in page with a fresh code. */
export async function answerCode(page: Page, secret: () => string) {
  const field = page.locator('input[autocomplete="one-time-code"]').first()
  await field.waitFor({ timeout: 20_000 })
  await field.fill(await freshTotp(secret()))
}

/** Reads the session from the console's own proxy: its CSRF token and roles. */
async function session(page: Page) {
  return page.evaluate(async () => {
    const res = await fetch('/api/v1/admin/auth/validate', { credentials: 'same-origin' })
    return (await res.json()) as {
      csrf_token?: string
      roles?: string[]
      role?: string
      max_role?: string
    }
  })
}

/**
 * Elevates the saved session through the API (the same route the Elevate
 * dialog calls, with a fresh authenticator code in the step-up header), so the
 * page checks see every page's content. The dialog itself is checked in
 * elevation.spec.ts. Returns once the session is elevated.
 */
export async function ensureElevated(browser: Browser) {
  const c = credentials()
  const context = await browser.newContext({ storageState: STATE_FILE })
  try {
    const page = await context.newPage()
    await page.goto('/')
    const s = await session(page)
    const role = s.roles?.includes('platform_owner')
      ? 'platform_owner'
      : (s.max_role ?? s.role ?? 'super_admin')
    const code = await freshTotp(c.totpSecret)
    const status = await page.evaluate(
      async ({ role, code, csrf }) => {
        const res = await fetch('/api/v1/admin/auth/elevate', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrf ?? '',
            'X-Admin-Step-Up': code,
          },
          body: JSON.stringify({ role, minutes: 60, reason: 'console e2e page checks' }),
        })
        return res.status
      },
      { role, code, csrf: s.csrf_token }
    )
    if (status >= 300) throw new Error(`elevation answered ${status}`)
    await context.storageState({ path: STATE_FILE })
  } finally {
    await context.close()
  }
}
