import { test, expect } from '../fixtures/authenticated-page'
import type { Page, Route } from '@playwright/test'

/**
 * Every state of the findings list. The list is in exactly one of them, and
 * each says what to do next (docs/findings-list.md, "Empty and error states"):
 * first run, no match, load error, no access, stale and partial counts. The
 * API answers are stubbed where the seed cannot produce the state, so each
 * test stands alone.
 */

const isList = (url: URL) => url.pathname === '/api/v1/findings'
const isStats = (url: URL) => url.pathname === '/api/v1/findings/stats'

const json = (route: Route, status: number, body: unknown) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

const EMPTY_LIST = {
  data: [],
  total: 0,
  page: 1,
  per_page: 25,
  total_pages: 0,
}
const EMPTY_STATS = {
  total: 0,
  by_severity: {},
  by_status: {},
  by_source: {},
  open_count: 0,
  resolved_count: 0,
  by_state: { open: 0, fixed: 0, dispositioned: 0, all: 0 },
}
const FORBIDDEN = {
  error: {
    code: 'FORBIDDEN',
    message: 'forbidden',
    details: { missing_permissions: ['findings:read'] },
  },
}

// The table and the phone cards each hold the state; one of them shows.
const emptyState = (page: Page) =>
  page.getByTestId('findings-empty-state').filter({ visible: true })
const search = (page: Page) => page.getByRole('searchbox', { name: /search findings/i })
const heading = (page: Page) => page.getByRole('heading', { name: 'Findings', level: 1 })

async function stubFirstRun(page: Page) {
  await page.route(isList, (route) => json(route, 200, EMPTY_LIST))
  await page.route(isStats, (route) => json(route, 200, EMPTY_STATS))
}

/** The page is not wider than the viewport (no sideways scroll). */
async function expectNoSidewaysScroll(page: Page) {
  const over = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth
  )
  expect(over).toBeLessThanOrEqual(0)
}

/** The state's actions, top to bottom, one per line and equally wide. */
async function expectStacked(page: Page) {
  const boxes = await emptyState(page)
    .locator('[data-slot=empty-actions] > *')
    .evaluateAll((els) =>
      els.map((el) => {
        const r = el.getBoundingClientRect()
        return { top: r.top, bottom: r.bottom, left: r.left, width: r.width }
      })
    )
  for (let i = 1; i < boxes.length; i++) {
    expect(boxes[i].top).toBeGreaterThanOrEqual(boxes[i - 1].bottom)
    expect(Math.abs(boxes[i].left - boxes[0].left)).toBeLessThanOrEqual(1)
    expect(Math.abs(boxes[i].width - boxes[0].width)).toBeLessThanOrEqual(1)
  }
}

test.describe('Findings list states', { tag: ['@findings'] }, () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
  })

  test('first run: the state alone, one filled action, no toolbar, count or header controls', async ({
    page,
  }) => {
    await stubFirstRun(page)
    await page.goto('/findings')
    const state = emptyState(page)
    await expect(state).toBeVisible({ timeout: 20_000 })
    await expect(state).toHaveAttribute('data-kind', 'nothing')
    await expect(state.getByText('No findings yet')).toBeVisible()

    // The actions: Run a scan (the one filled button), Import results, Connect a tool.
    const scan = state.getByRole('link', { name: 'Run a scan' })
    await expect(scan).toHaveAttribute('href', '/scans?new=scan')
    await expect(state.getByRole('link', { name: 'Connect a tool' })).toHaveAttribute(
      'href',
      '/settings/integrations'
    )
    const heights = await state
      .locator('[data-slot=empty-actions] [data-slot=button]')
      .evaluateAll((els) => els.map((el) => Math.round(el.getBoundingClientRect().height)))
    expect(heights.length).toBe(3)
    for (const h of heights) expect(h).toBe(32)

    // No toolbar, chips row, title row or count; the page header stays.
    await expect(heading(page)).toBeVisible()
    await expect(search(page)).toHaveCount(0)
    await expect(page.locator('[data-slot=filter-chips-row]')).toHaveCount(0)
    await expect(page.getByTestId('findings-toolbar-primary')).toHaveCount(0)
    await expect(page.locator('[data-slot=list-count]')).toHaveCount(0)
    await expect(page.getByRole('button', { name: /^Triage/ })).toBeVisible()

    // The table header offers neither select-all nor sorting.
    await expect(
      page.getByRole('checkbox', { name: 'Select all rows on this page' })
    ).toBeDisabled()
    await expect(page.locator('thead button:not([role=checkbox])')).toHaveCount(0)
    // No pager on an empty list.
    await expect(page.locator('[data-slot=data-table-pager]')).toHaveCount(0)

    // Import results opens the import dialog.
    await state.getByRole('button', { name: 'Import results' }).click()
    await expect(page.getByRole('dialog')).toBeVisible()
  })

  test('no match: the toolbar stays, the count reads 0, and the state clears the search', async ({
    page,
  }) => {
    await page.goto('/findings?q=zz-no-such-finding-63')
    const state = emptyState(page)
    await expect(state).toBeVisible({ timeout: 20_000 })
    await expect(state).toHaveAttribute('data-kind', 'no_match')
    await expect(state.getByText('No findings match')).toBeVisible()
    await expect(search(page)).toHaveValue('zz-no-such-finding-63')
    await expect(page.locator('[data-slot=list-count]')).toHaveCount(1)
    await expect(page.locator('[data-slot=list-count]')).toContainText('0')
    // The State lens is what it widens: "states", not "statuses".
    await expect(state.getByRole('button', { name: 'Search all states' })).toBeVisible()
    await expect(state.getByRole('button', { name: /statuses/i })).toHaveCount(0)
    await state.getByRole('button', { name: 'Clear search' }).click()
    await expect(page).not.toHaveURL(/q=zz-no-such-finding-63/)
  })

  test('no match with a filter: the chip stays and Clear filters removes it', async ({ page }) => {
    await page.route(isList, (route) => json(route, 200, EMPTY_LIST))
    await page.goto('/findings?severity=critical')
    const state = emptyState(page)
    await expect(state).toBeVisible({ timeout: 20_000 })
    await expect(state).toHaveAttribute('data-kind', 'no_match')
    await expect(page.locator('[data-slot=filter-chips-row]')).toBeVisible()
    await state.getByRole('button', { name: 'Clear filters' }).click()
    await expect(page).not.toHaveURL(/severity=critical/)
  })

  test('load error: an inline alert with Retry and Copy request ID, no count, no footer, no toast', async ({
    page,
  }) => {
    await page.route(isList, (route) =>
      json(route, 500, {
        error: { code: 'INTERNAL_ERROR', message: 'database is down', request_id: 'req-e2e-63' },
      })
    )
    await page.goto('/findings')
    await expect(page.getByRole('alert').filter({ hasText: /couldn't load/i })).toBeVisible({
      timeout: 20_000,
    })
    await expect(page.getByRole('button', { name: /retry/i })).toBeVisible()
    await expect(page.getByRole('button', { name: /copy request id/i })).toBeVisible()
    // The page chrome stays.
    await expect(heading(page)).toBeVisible()
    await expect(search(page)).toBeVisible()
    // No count (its slot is empty), no footer, and one message only.
    await expect(page.locator('[data-slot=list-count]')).toHaveText('')
    await expect(page.locator('[data-slot=data-table-pager]')).toHaveCount(0)
    await expect(page.locator('[data-slot=table-stale]')).toHaveCount(0)
    await expect(emptyState(page)).toHaveCount(0)
    await expect(page.locator('[data-sonner-toast]')).toHaveCount(0)
  })

  test('no access: says the viewer cannot read findings, one action, no controls that cannot work', async ({
    page,
  }) => {
    await page.route(isList, (route) => json(route, 403, FORBIDDEN))
    await page.goto('/findings')
    const state = emptyState(page)
    await expect(state).toBeVisible({ timeout: 20_000 })
    await expect(state).toHaveAttribute('data-kind', 'no_access')
    await expect(state.getByText('You cannot read findings here')).toBeVisible()

    // One action, at the default control height.
    const actions = state.locator('[data-slot=empty-actions] [data-slot=button]')
    await expect(actions).toHaveCount(1)
    const dashboard = state.getByRole('link', { name: 'Go to the dashboard' })
    await expect(dashboard).toHaveAttribute('href', '/')
    expect(Math.round((await dashboard.boundingBox())!.height)).toBe(32)
    await expect(page.getByText(/request access/i)).toHaveCount(0)

    // The header keeps its title, without Add finding and Triage.
    await expect(heading(page)).toBeVisible()
    await expect(page.getByRole('button', { name: 'Add finding' })).toHaveCount(0)
    await expect(page.getByRole('button', { name: /^Triage/ })).toHaveCount(0)
    // No toolbar, title row or count.
    await expect(search(page)).toHaveCount(0)
    await expect(page.getByTestId('findings-toolbar-primary')).toHaveCount(0)
    await expect(page.locator('[data-slot=list-count]')).toHaveCount(0)
    // "t" does not start triage here.
    await page.keyboard.press('t')
    await expect(page).toHaveURL(/\/findings$/)
  })

  test('stale: a failed refresh keeps the rows and says how old they are', async ({ page }) => {
    let fail = false
    await page.route(isList, (route) =>
      fail
        ? json(route, 500, { error: { code: 'INTERNAL_ERROR', message: 'database is down' } })
        : route.continue()
    )
    await page.goto('/findings')
    const rows = page.locator('tbody tr')
    const seeded = await rows
      .first()
      .waitFor({ state: 'visible', timeout: 20_000 })
      .then(() => true)
      .catch(() => false)
    test.skip(!seeded || (await emptyState(page).count()) > 0, 'the seed has no open finding')
    const before = await rows.count()
    // A fresh read says nothing about its age.
    await expect(page.locator('[data-slot=table-stale]')).toHaveCount(0)

    fail = true
    await page.getByRole('button', { name: 'Refresh', exact: true }).first().click()
    const stale = page.locator('[data-slot=table-stale]')
    await expect(stale).toBeVisible({ timeout: 20_000 })
    await expect(stale).toContainText(/Updated/)
    // The rows and the pager stay; the failure is not an alert in their place.
    await expect(rows).toHaveCount(before)
    await expect(page.locator('[data-slot=data-table-pager]')).toBeVisible()
    await expect(page.getByRole('alert').filter({ hasText: /couldn't load/i })).toHaveCount(0)
    const refresh = stale.getByRole('button', { name: 'Refresh now' })
    expect(Math.round((await refresh.boundingBox())!.height)).toBe(32)

    // A refresh that answers clears the note.
    fail = false
    await refresh.click()
    await expect(stale).toHaveCount(0, { timeout: 20_000 })
    await expect(rows).toHaveCount(before)
  })

  // The answer is stubbed: the list API always sends a total today, so the
  // page reads a missing or negative one as "not known".
  test('partial counts: Could not count with Retry, no total in the pager, Last page disabled', async ({
    page,
  }) => {
    let unknown = true
    await page.route(isList, async (route) => {
      const response = await route.fetch()
      const body = await response.json()
      if (unknown && body && typeof body === 'object') body.total = -1
      await route.fulfill({ response, json: body })
    })
    await page.goto('/findings')
    const rows = page.locator('tbody tr')
    const seeded = await rows
      .first()
      .waitFor({ state: 'visible', timeout: 20_000 })
      .then(() => true)
      .catch(() => false)
    test.skip(!seeded || (await emptyState(page).count()) > 0, 'the seed has no open finding')

    const count = page.locator('[data-slot=list-count]')
    await expect(count).toHaveCount(1)
    await expect(count).toHaveAttribute('data-state', 'failed')
    await expect(count).toContainText('Could not count')
    const pager = page.locator('[data-slot=data-table-pager]')
    await expect(pager).toContainText(/Showing 1 to \d+/)
    await expect(pager).not.toContainText(/ of \d/)
    await expect(pager).toContainText(/Page 1(?! of)/)
    const last = pager.getByRole('button', { name: 'Last page' })
    await expect(last).toBeDisabled()
    await expect(pager.locator('[data-slot=table-last-page]')).toHaveAttribute(
      'title',
      'The total is not known yet'
    )

    // Retry asks again; with a total the count and the pager are whole.
    unknown = false
    await page.locator('[data-slot=list-count-retry]').click()
    await expect(count).not.toHaveAttribute('data-state', 'failed', { timeout: 20_000 })
    await expect(pager).toContainText(/Showing 1 to \d+ of \d/)
  })
})

test.describe('Findings list states on a phone', { tag: ['@findings', '@phone'] }, () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
  })

  test('first run: the same copy and actions, stacked, no sideways scroll', async ({ page }) => {
    await stubFirstRun(page)
    await page.goto('/findings')
    const state = emptyState(page)
    await expect(state).toBeVisible({ timeout: 20_000 })
    await expect(state.getByText('No findings yet')).toBeVisible()
    await expect(state.getByRole('link', { name: 'Run a scan' })).toBeVisible()
    await expect(state.getByRole('button', { name: 'Import results' })).toBeVisible()
    await expect(state.getByRole('link', { name: 'Connect a tool' })).toBeVisible()
    await expect(search(page)).toHaveCount(0)
    await expectStacked(page)
    await expectNoSidewaysScroll(page)
    await page.setViewportSize({ width: 375, height: 812 })
    await expectNoSidewaysScroll(page)
  })

  test('no access: the one action, no sideways scroll', async ({ page }) => {
    await page.route(isList, (route) => json(route, 403, FORBIDDEN))
    await page.goto('/findings')
    const state = emptyState(page)
    await expect(state).toBeVisible({ timeout: 20_000 })
    await expect(state.getByText('You cannot read findings here')).toBeVisible()
    const dashboard = state.getByRole('link', { name: 'Go to the dashboard' })
    await expect(dashboard).toBeVisible()
    expect(Math.round((await dashboard.boundingBox())!.height)).toBe(36)
    await expect(page.getByRole('button', { name: /^Triage/ })).toHaveCount(0)
    await expectNoSidewaysScroll(page)
    await page.setViewportSize({ width: 375, height: 812 })
    await expectNoSidewaysScroll(page)
  })

  test('no match: the count reads 0 and the state clears the search', async ({ page }) => {
    await page.goto('/findings?q=zz-no-such-finding-63')
    const state = emptyState(page)
    await expect(state).toBeVisible({ timeout: 20_000 })
    await expect(state).toHaveAttribute('data-kind', 'no_match')
    await expect(state.getByRole('button', { name: 'Search all states' })).toBeVisible()
    await expectStacked(page)
    await expectNoSidewaysScroll(page)
    await state.getByRole('button', { name: 'Clear search' }).click()
    await expect(page).not.toHaveURL(/q=zz-no-such-finding-63/)
  })
})
