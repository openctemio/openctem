import { readFileSync } from 'node:fs'
import path from 'node:path'
import type { BrowserContext, Page } from '@playwright/test'
import { expect, test } from '@playwright/test'
import {
  type FederatedKind,
  type JourneyEnv,
  JourneyWatch,
  type OrgRules,
  type Outcome,
  type Person,
  type Profile,
  enrollFactor,
  federate,
  handOver,
  invite,
  journeyEnv,
  lit,
  newEmail,
  ownerSession,
  register,
  setRules,
  sql,
  totp,
} from '../helpers/journeys'

/**
 * @auth Sign-in journeys: a person arrives with one sign-in method, meets the
 * journeys organization under one rule (open, two-factor required, identity
 * provider required) as a first-time invitee or a returning member, and the
 * console must take them to the organization or to a page that names the
 * one next step. Never a logout loop, never an unexplained trip to /login.
 *
 * Journeys that fail on the current code are listed in
 * e2e/sign-in-journeys.known-failures.txt with the expected outcome; they run
 * as expected failures (test.fail), so a fixed one fails until its line goes.
 *
 * Design: server/docs/development/auth-scenarios.md
 */

type Method = 'password' | 'password-totp' | FederatedKind
type Rule = 'open' | '2fa-required' | 'idp-required'
type Membership = 'no-organization' | 'first-time-invited' | 'returning-member'
type Expect = 'in-org' | 'account-space' | 'told-why'

const RULES: Record<Rule, OrgRules> = {
  open: {},
  '2fa-required': { mfaRequired: true },
  'idp-required': { ssoEnforced: true },
}

/** The specification, as in server/tests/authscenarios/model_test.go. */
function expected(m: Method, r: Rule | null): Expect {
  if (r === null) return 'account-space'
  if (m === 'other-org-idp') return 'told-why' // sign in with your own account
  if (r === 'idp-required') return m === 'org-oidc' ? 'in-org' : 'told-why'
  // open, or two-factor required: our second step happens in the console.
  return 'in-org'
}

type Journey = { title: string; m: Method; r: Rule | null; mb: Membership }

function journeys(): Journey[] {
  const out: Journey[] = []
  // An authenticator only changes the outcome where two-factor is required
  // (each code waits for a fresh 30-second window, so it stays on that rule).
  for (const mb of ['first-time-invited', 'returning-member'] as const) {
    out.push({
      title: `${mb} / password-totp / 2fa-required`,
      m: 'password-totp',
      r: '2fa-required',
      mb,
    })
  }
  const full: Method[] = ['password', 'google', 'org-oidc', 'other-org-idp']
  for (const m of full) {
    out.push({ title: `no-organization / ${m}`, m, r: null, mb: 'no-organization' })
    for (const mb of ['first-time-invited', 'returning-member'] as const) {
      for (const r of ['open', '2fa-required', 'idp-required'] as const) {
        out.push({ title: `${mb} / ${m} / ${r}`, m, r, mb })
      }
    }
  }
  for (const m of ['microsoft', 'github'] as const) {
    out.push({ title: `no-organization / ${m}`, m, r: null, mb: 'no-organization' })
    out.push({
      title: `first-time-invited / ${m} / 2fa-required`,
      m,
      r: '2fa-required',
      mb: 'first-time-invited',
    })
  }
  return out
}

function knownFailures(): Set<string> {
  const file = path.resolve(__dirname, '../sign-in-journeys.known-failures.txt')
  return new Set(
    readFileSync(file, 'utf8')
      .split('\n')
      .map((l) => l.split('#')[0].trim())
      .filter(Boolean)
  )
}

const cfg = journeyEnv()
const KNOWN = knownFailures()

test.describe('sign-in journeys', { tag: ['@auth'] }, () => {
  // One organization whose rules each journey switches: the journeys run in
  // order in one worker, and a failure does not skip the next journey.
  test.describe.configure({ mode: 'default' })
  test.skip(!cfg.ok, `needs ${cfg.ok ? '' : cfg.missing.join(', ')} (web/e2e/ci/seed.sh)`)

  let env: JourneyEnv
  let owner: Profile
  let orgId = ''
  let homeOrgId = ''

  test.beforeAll(async () => {
    if (!cfg.ok) return
    env = cfg.env
    setRules(env, {})
    ;({ owner, orgId } = await ownerSession(env))
    homeOrgId = sql(env, `SELECT id FROM tenants WHERE slug = ${lit(env.homeSlug)}`)
  })

  test.afterEach(() => {
    if (cfg.ok) setRules(cfg.env, {})
  })

  /** Seeds the person and the session the method leaves; returns the start URL. */
  async function seed(
    context: BrowserContext,
    j: Journey,
    watch: JourneyWatch
  ): Promise<{ person: Person; start: string }> {
    setRules(env, {})
    const tok = await owner.call('POST', '/api/v1/auth/token', { tenant_id: orgId })
    if (tok.status === 200) owner.bearer = String(tok.body.access_token)
    const email = newEmail(j.m.replace(/-/g, ''))
    const invitation = await invite(env, owner, email)
    const person = await register(env, email, invitation)
    // The browser signs in from the person's own address, like the API calls
    // that seeded them. Otherwise every journey signs in from the one address
    // of the runner's browser, and the API's limit of five sign-ins a minute
    // per address ("Too many attempts") refuses a journey that runs close
    // after a few others. Test only; production limits are unchanged.
    await context.setExtraHTTPHeaders({ 'X-Forwarded-For': person.p.ip })
    if (j.m === 'password-totp') await enrollFactor(env, person)

    const federated = j.m !== 'password' && j.m !== 'password-totp'
    let access = ''
    if (j.mb === 'returning-member' && j.m === 'other-org-idp') {
      // The person joined with their own account; the other organization's
      // provider signs them in later (it never opens this organization).
      await person.p.ok('POST', '/api/v1/invitations/accept-with-refresh', { token: invitation })
    }
    if (federated) {
      federate(env, person, j.m as FederatedKind, orgId, homeOrgId)
      // The callback's access token is an account token (no organization yet).
      const at = await person.p.call('POST', '/api/v1/auth/account-token', {})
      if (at.status === 200) access = String(at.body.access_token)
    }
    let tenantCookie = ''
    if (j.mb === 'returning-member' && j.m !== 'other-org-idp') {
      await person.p.ok('POST', '/api/v1/invitations/accept-with-refresh', { token: invitation })
      if (j.m === 'org-oidc') {
        // The organization's provider signs in to that organization: its
        // callback stores an organization token and the organization.
        const t = await person.p.ok('POST', '/api/v1/auth/token', { tenant_id: orgId })
        access = String(t.body.access_token)
        tenantCookie = env.slug
      }
    }
    if (j.r) setRules(env, RULES[j.r])

    const invitationURL = `/invitations#token=${invitation}`
    if (federated) {
      await handOver(context, env, person, access, tenantCookie)
      return { person, start: j.mb === 'first-time-invited' ? invitationURL : '/' }
    }
    if (j.mb === 'first-time-invited') return { person, start: invitationURL }
    watch.openedLogin()
    return { person, start: '/login' }
  }

  for (const j of journeys()) {
    test(j.title, async ({ page, context }) => {
      test.fail(KNOWN.has(j.title), 'listed in e2e/sign-in-journeys.known-failures.txt')
      test.setTimeout(150_000)
      const watch = new JourneyWatch(page)
      const { person, start } = await seed(context, j, watch)
      await page.goto(start)
      const outcome = await drive(page, j, person, watch, env)
      const want = expected(j.m, j.r)
      const problems = watch.problems(outcome)
      const got = describeOutcome(outcome)
      if (want === 'in-org' && !(outcome.kind === 'in-org' && outcome.slug === env.slug)) {
        problems.push(`expected to work inside ${env.slug}, ended ${got}`)
      }
      if (want === 'account-space' && outcome.kind !== 'account-space') {
        problems.push(`expected the account space (welcome), ended ${got}`)
      }
      if (want === 'told-why') {
        if (outcome.kind === 'in-org' && outcome.slug === env.slug) {
          problems.push('BYPASS: the organization opened for a session its rules refuse')
        } else if (!(
          outcome.kind === 'explained' ||
          (outcome.kind === 'login' && outcome.reason)
        )) {
          problems.push(`expected a page that says why and what to do, ended ${got}`)
        }
      }
      expect(
        problems,
        `${j.title}\n  pages: ${watch.visits.join(' > ')}\n  refused: ${watch.refusals.join(', ')}`
      ).toEqual([])
    })
  }

  // --- while signed in ------------------------------------------------------

  for (const m of ['password', 'google'] as const) {
    const title = `while-signed-in / ${m} / 2fa-turned-on`
    test(title, async ({ page, context }) => {
      test.fail(KNOWN.has(title), 'listed in e2e/sign-in-journeys.known-failures.txt')
      test.setTimeout(150_000)
      const watch = new JourneyWatch(page)
      const j: Journey = { title, m, r: 'open', mb: 'returning-member' }
      const { person, start } = await seed(context, j, watch)
      await page.goto(start)
      let outcome = await drive(page, j, person, watch, env)
      expect(outcome.kind, `signed in first: ${describeOutcome(outcome)}`).toBe('in-org')
      setRules(env, RULES['2fa-required'])
      await page.reload()
      outcome = await drive(page, j, person, watch, env)
      const problems = watch.problems(outcome)
      if (!(outcome.kind === 'in-org' && outcome.slug === env.slug)) {
        problems.push(
          `expected the second step and then the organization, ended ${describeOutcome(outcome)}`
        )
      }
      expect(problems, `pages: ${watch.visits.join(' > ')}`).toEqual([])
    })
  }

  test('while-signed-in / password / access-suspended', async ({ page, context }) => {
    const title = 'while-signed-in / password / access-suspended'
    test.fail(KNOWN.has(title), 'listed in e2e/sign-in-journeys.known-failures.txt')
    test.setTimeout(150_000)
    const watch = new JourneyWatch(page)
    const j: Journey = { title, m: 'password', r: 'open', mb: 'returning-member' }
    const { person, start } = await seed(context, j, watch)
    await page.goto(start)
    let outcome = await drive(page, j, person, watch, env)
    expect(outcome.kind).toBe('in-org')
    await owner.ok(
      'POST',
      `/api/v1/tenants/${env.slug}/members/${membershipId(env, person)}/suspend`,
      {
        reason: 'journey',
      }
    )
    await page.reload()
    outcome = await drive(page, j, person, watch, env)
    const problems = watch.problems(outcome)
    if (outcome.kind === 'in-org' && outcome.slug === env.slug)
      problems.push('BYPASS: a suspended member still works inside')
    if (outcome.kind === 'login' && !outcome.reason) problems.push('logged out without a reason')
    expect(problems, `pages: ${watch.visits.join(' > ')}`).toEqual([])
  })

  test('invitation / for-another-email-while-signed-in', async ({ page, context }) => {
    const title = 'invitation / for-another-email-while-signed-in'
    test.fail(KNOWN.has(title), 'listed in e2e/sign-in-journeys.known-failures.txt')
    test.setTimeout(150_000)
    const watch = new JourneyWatch(page)
    const j: Journey = { title, m: 'google', r: null, mb: 'no-organization' }
    const { person } = await seed(context, j, watch)
    const other = await invite(env, owner, newEmail('someoneelse'))
    await page.goto(`/invitations#token=${other}`)
    const outcome = await drive(page, j, person, watch, env)
    const problems = watch.problems(outcome)
    if (outcome.kind === 'in-org')
      problems.push('BYPASS: joined with an invitation addressed to someone else')
    if (outcome.kind === 'login' && !outcome.reason)
      problems.push('signed out instead of explaining the mismatch')
    const members = sql(
      env,
      `SELECT count(*) FROM tenant_members WHERE user_id = ${lit(person.id)}`
    )
    if (members !== '0') problems.push('BYPASS: a membership was created')
    expect(problems, `pages: ${watch.visits.join(' > ')}`).toEqual([])
  })
})

function describeOutcome(o: Outcome): string {
  switch (o.kind) {
    case 'in-org':
      return `inside ${o.slug || '(no organization cookie)'}`
    case 'account-space':
      return 'in the account space'
    case 'login':
      return o.reason ? 'on /login with a reason' : 'on /login with no reason'
    case 'explained':
      return `on a page titled "${o.title}"`
    case 'stuck':
      return `stuck: ${o.detail}`
  }
}

async function settle(page: Page): Promise<void> {
  await page.waitForLoadState('domcontentloaded').catch(() => {})
  await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => {})
  await page.waitForTimeout(500)
}

async function visible(page: Page, loc: ReturnType<Page['locator']>): Promise<boolean> {
  return loc
    .first()
    .isVisible()
    .catch(() => false)
}

/** Sets up an authenticator on whatever second-step form is showing. */
async function enrollOnPage(page: Page, person: Person): Promise<void> {
  const key = page
    .locator('code')
    .filter({ hasText: /^[A-Z2-7 ]{8,}$/ })
    .first()
  const secret = ((await key.textContent()) ?? '').replace(/\s/g, '')
  person.secret = secret
  // The code field submits itself once complete; the button is a fallback.
  await page
    .getByLabel('Authentication code')
    .first()
    .fill(await totp(secret))
  await clickIfEnabled(page, /turn on/i)
  await settle(page)
  const saved = page.getByRole('checkbox', { name: /saved my recovery codes/i })
  if (await visible(page, saved)) await saved.first().check()
  await clickIfEnabled(page, /saved my recovery codes|continue/i)
}

/** Clicks the first enabled button with that name, if one shows within a moment. */
async function clickIfEnabled(page: Page, name: RegExp): Promise<void> {
  const button = page.getByRole('button', { name }).first()
  await page.waitForTimeout(500)
  if (
    (await button.isVisible().catch(() => false)) &&
    (await button.isEnabled().catch(() => false))
  ) {
    await button.click({ timeout: 5_000 }).catch(() => {})
  }
}

/**
 * Plays the journey the way a person would: accept the invitation, sign in
 * when asked (password journeys), answer or set up the second step, pick the
 * organization; stops where the console leaves the person.
 */
async function drive(
  page: Page,
  j: Journey,
  person: Person,
  watch: JourneyWatch,
  env: JourneyEnv
): Promise<Outcome> {
  let signedIn = false
  let accepted = 0
  let opened = 0
  for (let i = 0; i < 16; i++) {
    await settle(page)
    const url = new URL(page.url())
    const p = url.pathname
    const enrollKey = page.getByRole('button', { name: 'Copy key' })
    const code = page.getByLabel('Authentication code')

    if (await visible(page, enrollKey)) {
      await enrollOnPage(page, person)
      continue
    }
    if (await visible(page, code)) {
      if (!person.secret)
        return {
          kind: 'stuck',
          detail: `a verify step for an account without an authenticator (${p})`,
        }
      await code.first().fill(await totp(person.secret))
      await clickIfEnabled(page, /verify/i)
      continue
    }
    if (p.startsWith('/invitations')) {
      const accept = page.getByRole('button', { name: 'Accept invitation' })
      const open = page.getByRole('button', { name: /^Open / })
      const signIn = page.getByRole('link', { name: /sign in/i })
      // The page loads its invitation after it opens: wait for one of its
      // answers before reading it, or a slow load reads as a dead end.
      await accept
        .or(open)
        .or(signIn)
        .first()
        .waitFor({ state: 'visible', timeout: 5_000 })
        .catch(() => {})
      if (await visible(page, accept)) {
        if (accepted > 0) {
          const said = await page
            .locator('[data-sonner-toast], [role="alert"]')
            .first()
            .textContent()
            .catch(() => '')
          return {
            kind: 'stuck',
            detail: `the invitation still offers Accept after a refused acceptance (${(said ?? '').trim()})`,
          }
        }
        accepted += 1
        await accept.first().click()
        continue
      }
      if (await visible(page, open)) {
        if (opened > 0) {
          return {
            kind: 'stuck',
            detail: 'the invitation page still offers Open after opening failed',
          }
        }
        opened += 1
        await open.first().click()
        continue
      }
      if (
        !signedIn &&
        (j.m === 'password' || j.m === 'password-totp') &&
        (await visible(page, signIn))
      ) {
        watch.openedLogin()
        await signIn.first().click()
        continue
      }
      const title =
        (await page
          .locator('[data-slot="card-title"], h1, h2')
          .first()
          .textContent()
          .catch(() => '')) ?? ''
      return { kind: 'explained', title: title.trim() }
    }
    if (p.startsWith('/login')) {
      const email = page.getByLabel('Email')
      if (
        !signedIn &&
        (j.m === 'password' || j.m === 'password-totp') &&
        (await visible(page, email))
      ) {
        await email.first().fill(person.email)
        await page.getByLabel('Password', { exact: true }).fill(person.password)
        await page.getByRole('button', { name: 'Sign in' }).click()
        signedIn = true
        // The sign-in is a request that has not started when the page looks
        // idle: wait for the console to move on (a refusal stays here).
        await page
          .waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 5_000 })
          .catch(() => {})
        continue
      }
      const reason =
        url.searchParams.has('reason') ||
        url.searchParams.has('error') ||
        (await visible(page, page.getByRole('alert'))) ||
        (await visible(page, page.locator('[data-sonner-toast]')))
      return { kind: 'login', reason }
    }
    if (p.startsWith('/welcome') || p.startsWith('/onboarding') || p.startsWith('/not-set-up')) {
      // The account space with a notice names why an organization did not
      // open and offers its one next step: a page that says why.
      const notice = page.getByTestId('welcome-notice')
      if (await visible(page, notice)) {
        const title =
          (await notice
            .first()
            .locator('[data-slot="alert-title"]')
            .first()
            .textContent()
            .catch(() => '')) ?? ''
        return { kind: 'explained', title: `account space: ${title.trim()}` }
      }
      return { kind: 'account-space' }
    }
    if (p.startsWith('/select-tenant')) {
      await page.getByText(new RegExp(`E2E Journeys`)).first().click()
      continue
    }
    if (p.startsWith('/two-factor-setup')) {
      const title =
        (await page
          .locator('[role="alert"]')
          .first()
          .textContent()
          .catch(() => '')) ?? ''
      if (title) return { kind: 'explained', title: `two-factor setup: ${title.trim()}` }
      await page.waitForTimeout(2_000)
      continue
    }
    // An application page: inside whichever organization the cookie names.
    const tenant = (await page.context().cookies()).find((c) => c.name === 'app_tenant')
    if (tenant) {
      let slug = ''
      const raw = decodeURIComponent(tenant.value)
      try {
        slug = String((JSON.parse(raw) as { slug?: string }).slug ?? '')
      } catch {
        slug = raw // the identity provider callback stores the bare slug
      }
      return { kind: 'in-org', slug }
    }
    if (i > 12) break
    await page.waitForTimeout(1_000)
  }
  void env
  return { kind: 'stuck', detail: `still at ${page.url()} after 16 steps` }
}

/** The person's membership id in the journeys organization (member routes take it). */
function membershipId(env: JourneyEnv, person: Person): string {
  return sql(
    env,
    `SELECT m.id FROM tenant_members m JOIN tenants t ON t.id = m.tenant_id
      WHERE t.slug = ${lit(env.slug)} AND m.user_id = ${lit(person.id)}`
  )
}
