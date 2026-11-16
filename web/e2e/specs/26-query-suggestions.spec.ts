import { test, expect } from '../fixtures/authenticated-page'
import type { Page } from '@playwright/test'

/**
 * The field suggestions of Query mode on the findings, assets and scans
 * lists: with nothing typed they lead with the fields people filter by and
 * end with record identifiers, under labelled groups; each row says what
 * the field means; the list keeps the page gutter on a phone and never
 * covers the field; nothing is sent to the server while typing. Needs no
 * particular data.
 */

const GUTTER = 16

const LISTS = [
  { path: '/findings', first: ['severity', 'state', 'status'], meaning: /critical, high/i },
  { path: '/assets', first: ['name', 'type', 'criticality'], meaning: /asset name/i },
  { path: '/scans', first: ['name', 'status', 'last_run_status'], meaning: /scan name/i },
] as const

async function openEmpty(page: Page, path: string) {
  await page.goto(`${path}?mode=query`)
  const box = page.getByRole('combobox', { name: /filter (scans )?as query text/i })
  await expect(box).toBeEnabled({ timeout: 20_000 })
  await page.waitForLoadState('networkidle')
  await box.click()
  await box.fill('')
  const list = page.getByRole('listbox', { name: /search suggestions/i })
  await expect(list).toBeVisible()
  // Let the popover finish its entry animation before measuring.
  await page.waitForFunction(
    () => document.querySelector('[role="listbox"]')?.getAnimations().length === 0
  )
  return { box, list }
}

const names = (page: Page) =>
  page
    .getByRole('listbox')
    .getByRole('option')
    .evaluateAll((els) => els.map((e) => e.querySelector('.font-mono')?.textContent ?? ''))

for (const l of LISTS) {
  test.describe(
    `Query suggestions on ${l.path}`,
    { tag: ['@findings', '@assets', '@scans'] },
    () => {
      test(`common fields first, identifiers last, each explained (1440)`, async ({ page }) => {
        await page.setViewportSize({ width: 1440, height: 900 })
        const { box, list } = await openEmpty(page, l.path)
        const all = await names(page)
        expect(all.slice(0, l.first.length)).toEqual([...l.first])
        expect(all).not.toContain('text_search')
        // Group headings label the groups; the first is Common, ids come last.
        const groups = list.getByRole('group')
        await expect(groups.first()).toHaveAccessibleName('Common')
        await expect(groups.last()).toHaveAccessibleName('Identifiers')
        const ids = await groups.last().locator('[role="option"] .font-mono').allTextContents()
        expect(ids).toContain('id')
        expect(all.indexOf('id')).toBeGreaterThan(all.length - ids.length - 1)
        // A row explains its field.
        await expect(list.getByRole('option').first()).toContainText(l.meaning)
        // Keyboard: the field points at the active row; Tab accepts it.
        await expect(box).toHaveAttribute('aria-activedescendant', /-0$/)
        await box.press('ArrowDown')
        await expect(box).toHaveAttribute('aria-activedescendant', /-1$/)
        await box.press('Tab')
        await expect(box).toHaveValue(l.first[1])
        // An exact name offers its operators, each said in words.
        await expect(list.getByRole('option').first()).toContainText(/is|at least/)
        await box.press('Escape')
        await expect(list).toBeHidden()
      })

      test(
        `keeps the gutter and the field clear on a phone (390)`,
        { tag: ['@phone'] },
        async ({ page }) => {
          await page.setViewportSize({ width: 390, height: 844 })
          const { box, list } = await openEmpty(page, l.path)
          const lb = (await list.boundingBox())!
          const fb = (await box.boundingBox())!
          expect(lb.x, 'left gutter').toBeGreaterThanOrEqual(GUTTER - 0.5)
          expect(lb.x + lb.width, 'right gutter').toBeLessThanOrEqual(390 - GUTTER + 0.5)
          expect(
            lb.y >= fb.y + fb.height - 0.5 || lb.y + lb.height <= fb.y + 0.5,
            'never over the field'
          ).toBe(true)
          // About eight rows show without scrolling; each row is one line.
          const visible = await list.getByRole('option').evaluateAll((els) => {
            const frame = els[0].closest('[role="listbox"]')!.getBoundingClientRect()
            return els
              .map((e) => e.getBoundingClientRect())
              .filter((r) => r.top >= frame.top - 0.5 && r.bottom <= frame.bottom + 0.5)
              .map((r) => r.height)
          })
          expect(visible.length).toBeGreaterThanOrEqual(6)
          expect(visible.length).toBeLessThanOrEqual(9)
          for (const h of visible) expect(h).toBeLessThanOrEqual(36)
          // A field name is never cut: its box is as wide as its text.
          const cut = await list
            .getByRole('option')
            .locator('.font-mono')
            .evaluateAll((els) => els.filter((e) => e.scrollWidth > e.clientWidth + 1).length)
          expect(cut).toBe(0)
        }
      )
    }
  )
}

test(
  'typing a field name sends nothing to the server',
  { tag: ['@findings'] },
  async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    const { box } = await openEmpty(page, '/findings')
    const seen: string[] = []
    page.on('request', (r) => {
      if (/\/api\/v1\/(query|findings)/.test(r.url())) seen.push(new URL(r.url()).pathname)
    })
    await box.pressSequentially('ke', { delay: 60 })
    await expect(page.getByRole('listbox').getByRole('option').first()).toContainText('kev')
    await expect(page.getByRole('listbox').getByRole('option').first()).toContainText(
      /known exploited/i
    )
    await box.pressSequentially('v=t', { delay: 60 })
    await expect(page.getByRole('listbox').getByRole('option').first()).toContainText('true')
    await page.waitForTimeout(800)
    expect(seen).toEqual([])
  }
)
