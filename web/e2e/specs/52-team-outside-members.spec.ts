import { test, expect } from '../fixtures/authenticated-page'
import type { Page } from '@playwright/test'

/**
 * A team with a member from outside the organization cannot carry full data
 * access (the API refuses with TEAM_EXTERNAL_FULL_DATA). The owner's report:
 * the refusal only arrived as a toast after clicking. Now the Roles tab
 * turns full-data roles off up front, names the outside member and offers
 * the ways forward, and the Members tab marks them. The API answers are
 * stubbed, so the stack needs no data; no request writes anything.
 */

const TEAM = '88888888-8888-4888-8888-888888888888'
const OUTSIDER = '77777777-7777-4777-8777-777777777777'

const team = {
  id: TEAM,
  tenant_id: '66666666-6666-4666-8666-666666666666',
  name: 'DevSecOps',
  slug: 'devsecops',
  group_type: 'security_team',
  is_active: true,
  member_count: 2,
  asset_count: 0,
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
}

const json = (body: unknown) => ({
  status: 200,
  contentType: 'application/json',
  body: JSON.stringify(body),
})

/** Opens a sheet tab, through the More menu where the tab row overflows (phone). */
async function openTab(page: Page, name: string) {
  await expect(page.getByRole('tab', { name: 'Overview' })).toBeVisible({ timeout: 30_000 })
  const tab = page.getByRole('tab', { name })
  if (await tab.isVisible()) return tab.click()
  await page.locator('[data-slot="tabs-more"]').click()
  await page.getByRole('menuitem', { name }).click()
}

async function stub(page: Page, writes: string[]) {
  await page.route(
    (url) => url.pathname.startsWith('/api/v1/groups') || url.pathname === '/api/v1/roles',
    (route) => {
      const req = route.request()
      const path = new URL(req.url()).pathname
      if (req.method() !== 'GET') {
        writes.push(`${req.method()} ${path}`)
        return route.fulfill({ status: 500, body: '{}' })
      }
      if (path === '/api/v1/groups') return route.fulfill(json({ groups: [team], total: 1 }))
      if (path === `/api/v1/groups/${TEAM}`)
        return route.fulfill(
          json({ ...team, outside_members: [{ user_id: OUTSIDER, name: 'Pat Contractor' }] })
        )
      if (path === `/api/v1/groups/${TEAM}/members`)
        return route.fulfill(
          json({
            items: [
              {
                user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                name: 'Ana Inside',
                email: 'ana@corp.test',
                role: 'lead',
                joined_at: '2026-10-01T00:00:00Z',
              },
              {
                user_id: OUTSIDER,
                name: 'Pat Contractor',
                email: 'pat@vendor.test',
                role: 'member',
                joined_at: '2026-10-01T00:00:00Z',
                outside: true,
              },
            ],
            total_count: 2,
            page: 1,
            per_page: 20,
          })
        )
      if (path === `/api/v1/groups/${TEAM}/roles`) return route.fulfill(json({ data: [] }))
      if (path === `/api/v1/groups/${TEAM}/access`)
        return route.fulfill(json({ presets: [], scope_mode: 'specific', other_roles: 0 }))
      if (path === '/api/v1/roles')
        return route.fulfill(
          json({
            roles: [
              { id: 'r-analyst', name: 'Analyst', is_system: false, has_full_data_access: false },
              {
                id: 'r-full',
                name: 'Full data access',
                is_system: false,
                has_full_data_access: true,
              },
            ],
            total: 2,
          })
        )
      return route.fulfill(json({ items: [], data: [], total_count: 0 }))
    }
  )
}

test.describe('Team with outside members', { tag: ['@settings'] }, () => {
  test('full-data roles are off up front, with who and what to do', async ({ page }) => {
    const writes: string[] = []
    await stub(page, writes)
    await page.goto('/settings/teams')
    await page.getByText('DevSecOps').first().click({ timeout: 30_000 })

    await openTab(page, 'Roles')
    const notice = page.getByTestId('team-outside-notice')
    await expect(notice).toBeVisible()
    await expect(notice).toContainText('Pat Contractor')
    await expect(notice.getByRole('button', { name: 'New team without them' })).toBeVisible()
    await expect(notice.getByRole('button', { name: 'Give the role to a person' })).toBeVisible()

    await page.getByRole('combobox', { name: 'Role to add' }).click()
    await expect(page.getByRole('option', { name: /Full data access/ })).toHaveAttribute(
      'aria-disabled',
      'true'
    )
    await expect(page.getByRole('option', { name: 'Analyst' })).not.toHaveAttribute(
      'aria-disabled',
      'true'
    )
    await page.keyboard.press('Escape')

    // "Show them" opens the Members tab filtered to the outside member.
    await notice.getByRole('button', { name: 'Show them' }).click()
    await expect(page.getByTestId('member-outside-badge')).toHaveCount(1)
    await expect(page.getByText('Pat Contractor').first()).toBeVisible()
    await expect(page.getByText('Ana Inside')).toHaveCount(0)
    expect(writes).toEqual([])
  })

  test('the notice fits a phone without sideways scroll', { tag: '@phone' }, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await stub(page, [])
    await page.goto('/settings/teams')
    await page.getByText('DevSecOps').first().click({ timeout: 30_000 })
    await openTab(page, 'Roles')
    await expect(page.getByTestId('team-outside-notice')).toBeVisible()
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth
    )
    expect(overflow).toBeLessThanOrEqual(0)
  })
})
