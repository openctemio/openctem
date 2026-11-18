import fs from 'fs'
import type { Locator, Page, TestInfo } from '@playwright/test'
import { test, expect } from '../fixtures/authenticated-page'
import { RUN_STATUSES, scanRunFixtures, scanRunPage } from '../helpers/scan-run-fixtures'

/**
 * Phone cards stay compact whatever the data holds.
 *
 * Regression guarded (owner report 2026-11-17, /scans/runs at 390 px with real
 * runs): the first card showed "Status" with no value and then an empty box
 * taller than the screen. A run's message (every partial and failed run has
 * one) sat in the Status field as a one-line, cut text; the automatic card
 * lets cut texts wrap, so the message kept the field's overflow clip and
 * wrapped in the sliver of width beside the status chip, many lines tall and
 * clipped out of sight, while the chip sat at the middle of that height.
 * The fixtures of the runs list PR had no message, so its cards looked right.
 *
 *   1. /scans/runs, with a run of every status and every optional field absent
 *      and present: each card names its state, the first card stays under
 *      45% of the screen and no card is taller than 320 px.
 *   2. Every list with phone cards: no field label without a visible value
 *      next to it, and no card taller than the screen.
 */

const PHONE = { width: 390, height: 844 }
const CARD_MAX = 320
const FIRST_CARD_MAX = Math.round(PHONE.height * 0.45)

async function fulfilRuns(page: Page) {
  await page.route(
    (url) => url.pathname === '/api/v1/scan-runs',
    (route) =>
      route.request().method() === 'GET' ? route.fulfill({ json: scanRunPage() }) : route.fallback()
  )
}

type CardFacts = {
  height: number
  text: string
  /** Field labels with no visible text near them (the label's own line or the next). */
  emptyFields: string[]
}

/** Height, text and empty-looking fields of every phone card on the page. */
async function cardFacts(page: Page): Promise<CardFacts[]> {
  return page.locator('[data-phone-card]').evaluateAll((cards) =>
    cards.map((card) => {
      const visibleTextTop = (el: Element): number | null => {
        const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT)
        let top: number | null = null
        for (let n = walker.nextNode(); n; n = walker.nextNode()) {
          if (!(n.textContent ?? '').trim()) continue
          const parent = n.parentElement
          if (!parent || parent.closest('.sr-only')) continue
          const range = document.createRange()
          range.selectNodeContents(n)
          for (const r of Array.from(range.getClientRects())) {
            if (r.width < 1 || r.height < 1) continue
            // Clipped by an ancestor (overflow hidden) inside the card: not seen.
            let clipped = false
            for (let a: Element | null = parent; a && a !== card; a = a.parentElement) {
              const s = getComputedStyle(a)
              if (s.overflow === 'visible' && s.overflowX === 'visible') continue
              const box = a.getBoundingClientRect()
              if (
                r.right <= box.left + 1 ||
                r.left >= box.right - 1 ||
                r.bottom <= box.top + 1 ||
                r.top >= box.bottom - 1
              ) {
                clipped = true
                break
              }
            }
            if (clipped) continue
            if (top === null || r.top < top) top = r.top
          }
        }
        return top
      }
      const emptyFields: string[] = []
      for (const field of Array.from(card.querySelectorAll('[data-slot="mobile-card-field"]'))) {
        const dt = field.querySelector('dt')
        const dd = field.querySelector('dd')
        if (!dt || !dd) continue
        const top = visibleTextTop(dd)
        const below = dt.getBoundingClientRect().bottom
        // The value starts on the line under its label (a 24 px allowance).
        if (top === null || top > below + 24) emptyFields.push((dt.textContent ?? '').trim())
      }
      return {
        height: Math.round(card.getBoundingClientRect().height),
        text: (card.textContent ?? '').replace(/\s+/g, ' ').trim().slice(0, 80),
        emptyFields,
      }
    })
  )
}

/** Saves a measurement or screenshot in the test's output folder and attaches it. */
async function keep(testInfo: TestInfo, name: string, body: string | Buffer) {
  const file = testInfo.outputPath(name)
  fs.writeFileSync(file, body)
  await testInfo.attach(name, { path: file })
}

async function waitForCards(page: Page): Promise<Locator> {
  const cards = page.locator('[data-phone-card]')
  await expect(cards.first()).toBeVisible({ timeout: 45_000 })
  return cards
}

test.describe('Phone card bounds', { tag: ['@scans', '@phone'] }, () => {
  test('/scans/runs: every run status names its state in a compact card', async ({
    page,
  }, testInfo) => {
    await page.setViewportSize(PHONE)
    await fulfilRuns(page)
    await page.goto('/scans/runs')
    const cards = await waitForCards(page)
    const fixtures = scanRunFixtures()
    await expect(cards).toHaveCount(fixtures.length)

    const facts = await cardFacts(page)
    await keep(
      testInfo,
      'card-heights.txt',
      facts
        .map(
          (f, i) => `${i} ${fixtures[i].status} ${f.height}px empty=[${f.emptyFields}] ${f.text}`
        )
        .join('\n')
    )
    expect.soft(facts[0].height, 'first card').toBeLessThanOrEqual(FIRST_CARD_MAX)
    facts.forEach((f, i) => {
      expect
        .soft(f.height, `card ${i} (${fixtures[i].status}): ${f.text}`)
        .toBeLessThanOrEqual(CARD_MAX)
      expect.soft(f.emptyFields, `card ${i}: labels without a value`).toEqual([])
    })

    // The state slot of the first card of every status holds its word.
    for (const status of RUN_STATUSES) {
      const i = fixtures.findIndex((r) => r.status === status)
      const state = cards.nth(i).locator('[data-slot="health-status"]').first()
      await expect.soft(state, `${status}: state shown`).toBeVisible()
      await expect.soft(state, `${status}: state named`).not.toHaveText('')
      const box = await state.boundingBox()
      const card = await cards.nth(i).boundingBox()
      // The state sits in the card's first lines, not lost in its middle.
      expect
        .soft(box && card ? box.y - card.y : Infinity, `${status}: state near the top`)
        .toBeLessThan(96)
    }

    await cards.first().scrollIntoViewIfNeeded()
    await keep(testInfo, 'runs-390.png', await page.screenshot())
  })

  const ROUTES = [
    '/scans',
    '/scans/workflows',
    '/sensors',
    '/vulnerabilities',
    '/components',
    '/exposures',
    '/assets/changes',
    '/assets/attention/no-owner',
    '/assets/attention/unscanned',
    '/assets/attention/decide-monitoring',
    '/findings/approvals',
  ]

  test('lists with phone cards: no empty field, no card taller than the screen', async ({
    page,
  }, testInfo) => {
    test.setTimeout(300_000)
    await page.setViewportSize(PHONE)
    for (const route of ROUTES) {
      await page.goto(route)
      await expect(page.locator('main').first()).toBeVisible({ timeout: 45_000 })
      await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => {})
      // The rows, or the list's empty state, before measuring.
      await page
        .locator('[data-phone-card], [data-slot="table-empty"]')
        .first()
        .waitFor({ timeout: 20_000 })
        .catch(() => {})
      const facts = await cardFacts(page)
      const name = route.replace(/\W+/g, '-').replace(/^-/, '')
      await keep(
        testInfo,
        `${name}.txt`,
        facts.map((f, i) => `${i} ${f.height}px empty=[${f.emptyFields}] ${f.text}`).join('\n')
      )
      if (facts.length > 0) await page.locator('[data-phone-card]').first().scrollIntoViewIfNeeded()
      await keep(testInfo, `${name}.png`, await page.screenshot())
      facts.forEach((f, i) => {
        expect.soft(f.height, `${route} card ${i}: ${f.text}`).toBeLessThan(PHONE.height)
        expect.soft(f.emptyFields, `${route} card ${i}: labels without a value`).toEqual([])
      })
    }
  })
})
