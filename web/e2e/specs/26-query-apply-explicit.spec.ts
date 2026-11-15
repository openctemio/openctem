import { test, expect } from '../fixtures/authenticated-page'

/**
 * Query mode of the findings search field sends nothing to the server while
 * the person types: no parse, no list fetch, no count, no value lookup for a
 * one-character value. Enter applies: one check of the text and one list
 * fetch. Needs no particular data.
 */

const WATCHED = /\/api\/v1\/(query\/(parse|values)|findings(\?|$))/

test.describe('Query mode applies on request only', { tag: ['@findings'] }, () => {
  test('typing 20 characters sends nothing; Enter sends one check and one list fetch', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings')
    await page.getByRole('button', { name: /^query$/i }).click()
    const box = page.getByRole('combobox', { name: /filter as query text/i })
    await expect(box).toBeEnabled({ timeout: 20_000 })
    await page.waitForLoadState('networkidle')

    const seen: string[] = []
    page.on('request', (r) => {
      if (WATCHED.test(r.url())) seen.push(`${r.method()} ${new URL(r.url()).pathname}`)
    })
    await box.fill('')
    const text = 'severity>=high kev=t'
    expect(text).toHaveLength(20)
    await box.pressSequentially(text, { delay: 60 })
    await page.waitForTimeout(1500)
    expect(seen).toEqual([])
    // The edit is marked and announced, and the run control is enabled.
    await expect(page.getByText(/not applied yet/i)).toBeAttached()
    // A field the schema knows completes locally: no value lookup.
    await box.fill('severity>=high is_in_kev=true')
    await page.waitForTimeout(800)
    expect(seen).toEqual([])

    await box.press('Enter')
    await expect(page).toHaveURL(/is_in_kev=true/)
    await page.waitForLoadState('networkidle')
    const parses = seen.filter((s) => s.endsWith('/query/parse'))
    const lists = seen.filter((s) => s.startsWith('GET') && s.endsWith('/findings'))
    // One check on Enter; the page prints the new filter back once.
    expect(parses.length).toBeGreaterThanOrEqual(1)
    expect(parses.length).toBeLessThanOrEqual(2)
    expect(lists).toHaveLength(1)
    expect(seen.filter((s) => s.includes('/query/values'))).toEqual([])
    console.log(`requests after Enter: ${JSON.stringify(seen)}`)
  })

  test('Basic mode: typed search waits for a pause (one list fetch for a word)', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto('/findings')
    const search = page.getByRole('searchbox', { name: /search findings/i })
    await expect(search).toBeVisible({ timeout: 20_000 })
    await page.waitForLoadState('networkidle')
    const seen: string[] = []
    page.on('request', (r) => {
      if (WATCHED.test(r.url())) seen.push(`${r.method()} ${new URL(r.url()).pathname}`)
    })
    await search.pressSequentially('remote code', { delay: 60 })
    await page.waitForTimeout(1500)
    console.log(`basic-mode requests for 11 keys: ${JSON.stringify(seen)}`)
    expect(seen.filter((s) => s.endsWith('/findings')).length).toBeLessThanOrEqual(1)
    expect(seen.filter((s) => s.includes('/query/'))).toEqual([])
  })
})
