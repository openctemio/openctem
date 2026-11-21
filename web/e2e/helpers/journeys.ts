/**
 * Seeding and invariants for the sign-in journeys spec (58-sign-in-journeys).
 *
 * People and their sessions are seeded through the API, the way the console's
 * server side talks to it (refresh token in the cookie jar, CSRF pair, one
 * client address per person). A federated sign-in (Google, Microsoft, GitHub,
 * an organization's identity provider) cannot complete against a real
 * provider in the test stack, so its session is written as the provider's
 * callback leaves it (sessions.auth_method / idp_tenant_id, an account without
 * a password), and the browser receives the cookies the console's callback
 * route sets. Everything after the provider said yes is the real product.
 *
 * Design: server/docs/development/auth-scenarios.md
 */
import { createHmac, randomBytes, randomInt } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import type { BrowserContext, Page, Response } from '@playwright/test'

export type JourneyEnv = {
  api: string
  baseURL: string
  slug: string
  ownerEmail: string
  ownerPassword: string
  databaseURL: string
  network: string
  homeSlug: string
}

/** The journeys environment, or the names of the missing variables. */
export function journeyEnv(): { ok: true; env: JourneyEnv } | { ok: false; missing: string[] } {
  const need = {
    E2E_JOURNEY_SLUG: process.env.E2E_JOURNEY_SLUG,
    E2E_JOURNEY_OWNER_EMAIL: process.env.E2E_JOURNEY_OWNER_EMAIL,
    E2E_JOURNEY_OWNER_PASSWORD: process.env.E2E_JOURNEY_OWNER_PASSWORD,
    E2E_DATABASE_URL: process.env.E2E_DATABASE_URL,
    E2E_TENANT_SLUG: process.env.E2E_TENANT_SLUG,
  }
  const missing = Object.entries(need)
    .filter(([, v]) => !v)
    .map(([k]) => k)
  if (missing.length) return { ok: false, missing }
  const baseURL = process.env.E2E_BASE_URL ?? 'http://localhost:3000'
  return {
    ok: true,
    env: {
      api: process.env.E2E_API_BASE_URL ?? 'http://localhost:8080',
      baseURL,
      slug: need.E2E_JOURNEY_SLUG!,
      ownerEmail: need.E2E_JOURNEY_OWNER_EMAIL!,
      ownerPassword: need.E2E_JOURNEY_OWNER_PASSWORD!,
      databaseURL: need.E2E_DATABASE_URL!,
      network: process.env.E2E_JOURNEY_NETWORK ?? 'octe2e-ci_default',
      homeSlug: need.E2E_TENANT_SLUG!,
    },
  }
}

// --- database -------------------------------------------------------------

/** Quotes a value for SQL (the suite only passes its own ids and addresses). */
export function lit(v: string | null | boolean): string {
  if (v === null) return 'NULL'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  return `'${v.replace(/'/g, "''")}'`
}

/** Runs SQL in the stack's database (psql in a container on its network). */
export function sql(env: JourneyEnv, query: string): string {
  return execFileSync(
    'docker',
    [
      'run',
      '--rm',
      '-i',
      '--network',
      env.network,
      '-e',
      'PGCONNECT_TIMEOUT=10',
      process.env.PSQL_IMAGE ?? 'postgres:17-alpine',
      'psql',
      env.databaseURL,
      '-v',
      'ON_ERROR_STOP=1',
      '-qtA',
      '-c',
      query,
    ],
    { encoding: 'utf8', timeout: 60_000 }
  ).trim()
}

export type OrgRules = {
  mfaRequired?: boolean
  ssoEnforced?: boolean
}

/** Writes the organization's sign-in rules (no API changes them for an owner who cannot pass them). */
export function setRules(env: JourneyEnv, r: OrgRules): void {
  const sec = JSON.stringify({
    mfa_required: !!r.mfaRequired,
    mfa_required_for_admins: false,
    sso_enforced: !!r.ssoEnforced,
    sso_require_mfa_evidence: false,
  })
  sql(
    env,
    `UPDATE tenants SET settings = COALESCE(settings, '{}'::jsonb) || jsonb_build_object('security',
       COALESCE(settings->'security', '{}'::jsonb) || ${lit(sec)}::jsonb) WHERE slug = ${lit(env.slug)}`
  )
}

// --- TOTP -----------------------------------------------------------------

function base32(secret: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const c of secret.replace(/[\s=]/g, '').toUpperCase()) {
    const v = alphabet.indexOf(c)
    if (v < 0) continue
    bits += v.toString(2).padStart(5, '0')
  }
  const bytes: number[] = []
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2))
  return Buffer.from(bytes)
}

const usedCodes = new Map<string, string>()

/** A 6-digit code for the secret the server has not seen yet (codes are single use). */
export async function totp(secret: string): Promise<string> {
  for (let i = 0; i < 40; i++) {
    const counter = Math.floor(Date.now() / 30_000)
    const msg = Buffer.alloc(8)
    msg.writeBigUInt64BE(BigInt(counter))
    const h = createHmac('sha1', base32(secret)).update(msg).digest()
    const o = h[h.length - 1] & 0xf
    const code = (((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000) + '').padStart(6, '0')
    if (usedCodes.get(secret) !== code) {
      usedCodes.set(secret, code)
      return code
    }
    await new Promise((r) => setTimeout(r, 1000))
  }
  throw new Error('no fresh TOTP code within 40 s')
}

// --- API client ------------------------------------------------------------

export type ApiAnswer = { status: number; code: string; body: Record<string, unknown> }

/** One person's API profile: cookie jar, CSRF pair, own client address. */
export class Profile {
  cookies = new Map<string, string>()
  bearer = ''
  readonly ip: string

  constructor(private env: JourneyEnv) {
    // Random, not a counter: a retried test runs in a new worker, and a
    // repeated address would share the previous person's limits.
    // randomInt draws without the bias a modulo of random bytes has.
    this.ip = `198.18.${randomInt(0, 256)}.${randomInt(1, 251)}`
  }

  async call(method: string, path: string, body?: unknown): Promise<ApiAnswer> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-Forwarded-For': this.ip,
    }
    if (this.bearer) headers.Authorization = `Bearer ${this.bearer}`
    const csrf = this.cookies.get('csrf_token')
    if (csrf) headers['X-CSRF-Token'] = csrf
    if (this.cookies.size) {
      headers.Cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ')
    }
    const res = await fetch(this.env.api + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'manual',
    })
    for (const sc of res.headers.getSetCookie()) {
      const [pair, ...attrs] = sc.split(';')
      const i = pair.indexOf('=')
      const name = pair.slice(0, i).trim()
      const value = pair.slice(i + 1).trim()
      const expired = attrs.some((a) => /max-age=0\b|max-age=-/i.test(a.trim()))
      if (expired || value === '') this.cookies.delete(name)
      else this.cookies.set(name, value)
    }
    const text = await res.text()
    let parsed: Record<string, unknown> = {}
    try {
      parsed = text ? (JSON.parse(text) as Record<string, unknown>) : {}
    } catch {
      parsed = { raw: text.slice(0, 300) }
    }
    return {
      status: res.status,
      code: typeof parsed.code === 'string' ? parsed.code : '',
      body: parsed,
    }
  }

  async ok(method: string, path: string, body?: unknown): Promise<ApiAnswer> {
    const r = await this.call(method, path, body)
    if (r.status < 200 || r.status > 299) {
      throw new Error(
        `${method} ${path}: ${r.status} ${r.code} ${JSON.stringify(r.body).slice(0, 300)}`
      )
    }
    return r
  }

  get refreshToken(): string {
    return this.cookies.get('refresh_token') ?? ''
  }

  /** The session behind the refresh cookie (from the token's claims). */
  get sessionId(): string {
    const part = this.refreshToken.split('.')[1] ?? ''
    const claims = JSON.parse(Buffer.from(part, 'base64url').toString() || '{}') as {
      session_id?: string
    }
    if (!claims.session_id) throw new Error('no session id in the refresh cookie')
    return claims.session_id
  }
}

export const ROLE_MEMBER = '00000000-0000-0000-0000-000000000003'

/** The journeys organization's owner, signed in with an organization token. */
export async function ownerSession(env: JourneyEnv): Promise<{ owner: Profile; orgId: string }> {
  const owner = new Profile(env)
  const login = await owner.ok('POST', '/api/v1/auth/login', {
    email: env.ownerEmail,
    password: env.ownerPassword,
  })
  const tenants = (login.body.tenants as { id: string; slug: string }[] | undefined) ?? []
  const orgId = tenants.find((t) => t.slug === env.slug)?.id
  if (!orgId) throw new Error(`owner login lists no ${env.slug}`)
  const tok = await owner.ok('POST', '/api/v1/auth/token', { tenant_id: orgId })
  owner.bearer = String(tok.body.access_token)
  return { owner, orgId }
}

export function newEmail(label: string): string {
  return `journey-${label}-${randomBytes(4).toString('hex')}@example.com`
}

export async function invite(env: JourneyEnv, owner: Profile, email: string): Promise<string> {
  const r = await owner.ok('POST', `/api/v1/tenants/${env.slug}/invitations`, {
    email,
    role_ids: [ROLE_MEMBER],
  })
  return String(r.body.token)
}

export type Person = { email: string; password: string; id: string; secret?: string; p: Profile }

/** Signs up with a pending invitation (public sign-up is off) and signs in. */
export async function register(
  env: JourneyEnv,
  email: string,
  invitation: string
): Promise<Person> {
  const password = `Jr-${randomBytes(6).toString('hex')}-9x`
  const p = new Profile(env)
  await p.ok('POST', '/api/v1/auth/register', {
    email,
    password,
    name: 'Journey person',
    invitation_token: invitation,
  })
  const person: Person = { email, password, id: '', p }
  await signIn(env, person)
  return person
}

/** A new password session (answering the verify step with the known secret). */
export async function signIn(env: JourneyEnv, person: Person): Promise<void> {
  person.p = new Profile(env)
  const r = await person.p.ok('POST', '/api/v1/auth/login', {
    email: person.email,
    password: person.password,
  })
  if (r.body.mfa_token && r.body.mfa_purpose !== 'enroll') {
    if (!person.secret) throw new Error('verify step asked without a secret')
    await person.p.ok('POST', '/api/v1/auth/mfa/verify', {
      mfa_token: r.body.mfa_token,
      code: await totp(person.secret),
    })
  }
  const user = r.body.user as { id?: string } | undefined
  if (user?.id) person.id = user.id
  if (!person.id) {
    person.id = sql(env, `SELECT id FROM users WHERE lower(email) = lower(${lit(person.email)})`)
  }
}

/** Turns an authenticator on (from the account space) and signs in again with it. */
export async function enrollFactor(env: JourneyEnv, person: Person): Promise<void> {
  const at = await person.p.ok('POST', '/api/v1/auth/account-token', {})
  person.p.bearer = String(at.body.access_token)
  const setup = await person.p.ok('POST', '/api/v1/users/me/2fa/setup', {
    password: person.password,
  })
  person.secret = String(setup.body.secret)
  await person.p.ok('POST', '/api/v1/users/me/2fa/enable', {
    password: person.password,
    code: await totp(person.secret),
  })
  await signIn(env, person)
}

export type FederatedKind = 'google' | 'microsoft' | 'github' | 'org-oidc' | 'other-org-idp'

/**
 * Writes the person's current session as the federated sign-in leaves it.
 * Social and identity-provider accounts have no password; the other-IdP
 * person keeps their own.
 */
export function federate(
  env: JourneyEnv,
  person: Person,
  kind: FederatedKind,
  orgId: string,
  homeOrgId: string
): void {
  const idp = kind === 'org-oidc' ? orgId : kind === 'other-org-idp' ? homeOrgId : null
  sql(
    env,
    `UPDATE sessions SET auth_method = 'sso', idp_tenant_id = ${lit(idp)}, mfa_evidence = false
      WHERE id = ${lit(person.p.sessionId)}`
  )
  if (kind !== 'other-org-idp') {
    const provider = kind === 'org-oidc' ? 'oidc' : kind
    sql(
      env,
      `UPDATE users SET password_hash = NULL, auth_provider = ${lit(provider)} WHERE id = ${lit(person.id)}`
    )
  }
}

/**
 * Gives the browser the cookies the console's sign-in callback sets: the
 * session's refresh token and, when one exists, an access token.
 */
export async function handOver(
  context: BrowserContext,
  env: JourneyEnv,
  person: Person,
  access: string,
  tenant = ''
): Promise<void> {
  const url = new URL(env.baseURL)
  const base = {
    domain: url.hostname,
    path: '/',
    httpOnly: true,
    secure: false,
    sameSite: 'Lax' as const,
  }
  const cookies = [{ ...base, name: 'refresh_token', value: person.p.refreshToken }]
  if (access) cookies.push({ ...base, name: 'auth_token', value: access })
  if (tenant) cookies.push({ ...base, httpOnly: false, name: 'app_tenant', value: tenant })
  await context.addCookies(cookies)
}

// --- invariants --------------------------------------------------------------

export type Outcome =
  | { kind: 'in-org'; slug: string }
  | { kind: 'account-space' }
  | { kind: 'login'; reason: boolean }
  | { kind: 'explained'; title: string }
  | { kind: 'stuck'; detail: string }

/**
 * Records what the browser did during a journey: every page it reached and
 * every refused API answer. The invariants: no more than one unexplained trip
 * to the sign-in page (a logout loop shows as several), and a 401/403 is never
 * followed by an unexplained redirect to /login.
 */
export class JourneyWatch {
  readonly visits: string[] = []
  readonly refusals: string[] = []
  private explicitLogins = 0

  constructor(page: Page) {
    page.on('framenavigated', (f) => {
      if (f !== page.mainFrame()) return
      const u = new URL(f.url())
      const here = u.pathname + u.search
      // One entry per page reached: a client-side replace of the same path
      // (query cleanup, hydration) is not a second visit.
      const last = this.visits[this.visits.length - 1]
      if (last === undefined || last.split('?')[0] !== u.pathname) this.visits.push(here)
    })
    page.on('response', (r: Response) => {
      const u = new URL(r.url())
      if (
        (r.status() === 401 || r.status() === 403) &&
        (u.pathname.startsWith('/api/') || u.pathname.startsWith('/auth'))
      ) {
        this.refusals.push(`${r.status()} ${u.pathname}`)
      }
    })
  }

  /** The test itself opened /login (a password journey): not a redirect. */
  openedLogin(): void {
    this.explicitLogins += 1
  }

  loginVisits(): number {
    return this.visits.filter((v) => v.startsWith('/login')).length
  }

  /** Problems with the journey as a whole. */
  problems(outcome: Outcome): string[] {
    const out: string[] = []
    const extra = this.loginVisits() - this.explicitLogins
    if (extra > 1)
      out.push(
        `logout loop: /login reached ${extra} times without the test opening it (${this.visits.join(' > ')})`
      )
    if (outcome.kind === 'login' && !outcome.reason && extra > 0) {
      out.push(
        `unexplained redirect to /login after ${this.refusals.slice(-3).join(', ') || 'no refused request'}`
      )
    }
    if (outcome.kind === 'stuck') out.push(`no clear next step: ${outcome.detail}`)
    return out
  }
}
