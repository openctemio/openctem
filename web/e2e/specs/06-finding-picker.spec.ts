import { test, expect } from '../fixtures/authenticated-page'
import { firstDataRow } from '../helpers/table'

/**
 * Findings picker inside the remediation task drawer.
 *
 * Regression guard for the picker rework: the picker is an INLINE view that
 * replaces the drawer body (not a portaled Popover/Dialog/fixed panel), so it
 * scrolls via the Sheet's own overflow-y-auto — the only approach that touch-
 * scrolls on iPad (portaled overlays are blocked by the Sheet's
 * react-remove-scroll; a fixed child is trapped by the Sheet containing block).
 *
 * Verifies: open task drawer → Manage → inline "Link findings" panel renders →
 * open-findings count shows → list is scrollable → server-side search filters →
 * toggling a row flips its checkbox → Done returns to task details.
 */
test.describe('Remediation — findings picker', () => {
  test('inline picker renders, scrolls, searches and toggles', async ({ page }) => {
    await page.goto('/remediation')

    // The task table. If the tenant has no remediation tasks, there is nothing
    // to open — skip rather than fail (data-dependent). The empty table's
    // "No tasks found" row is not a task.
    const firstRow = await firstDataRow(page)
    test.skip(!firstRow, 'no remediation tasks in this tenant to open a drawer for')

    // Open the task detail drawer.
    await firstRow!.click()
    const drawer = page.getByRole('dialog')
    await expect(drawer).toBeVisible()
    // The task drawer's "Linked findings" section heading.
    await expect(drawer.getByRole('heading', { name: /Linked findings/i })).toBeVisible()

    // Enter the inline picker.
    await drawer.getByRole('button', { name: /Manage/i }).click()

    // The inline "Link findings" panel replaces the drawer body.
    const pickerHeading = drawer.getByRole('heading', { name: 'Link findings' })
    await expect(pickerHeading).toBeVisible()

    // The open-findings count subtitle ("N linked · M open findings").
    await expect(drawer.getByText(/open findings/i)).toBeVisible()

    // Search is server-side: typing narrows the list. We don't assert an exact
    // count (data-dependent) — only that typing holds the input value (the iPad
    // focus-loss bug this rework had to survive).
    const search = drawer.getByPlaceholder(/Search findings/i)
    await search.fill('a')
    await expect(search).toHaveValue('a')
    await search.fill('')

    // Wait for the findings list to finish loading before measuring scroll —
    // otherwise the skeleton hasn't overflowed yet and the check is racy.
    const findingRows = drawer.locator('button:has(> span[aria-hidden="true"])')
    await expect(findingRows.first()).toBeVisible({ timeout: 15_000 })
    await page.waitForLoadState('networkidle')
    const findingCount = await findingRows.count()

    // Scrolling only applies when the list overflows: it needs more findings
    // than fit (about ten). With fewer, the scroll check is skipped, not failed.
    if (findingCount > 10) {
      // Scrollability: the Sheet's SheetContent (= the dialog element, which has
      // overflow-y-auto) is the scroll host. It must overflow when the tenant has
      // many findings, and scrolling it must move scrollTop — this is the exact
      // "can't scroll on iPad" bug the whole rework had to fix.
      const metrics = await search.evaluate((inputEl) => {
        // Climb to the nearest actually-scrollable ancestor (the Sheet's scroll host).
        let node: HTMLElement | null = inputEl as HTMLElement
        while (node) {
          const style = getComputedStyle(node)
          const scrollable = /(auto|scroll)/.test(style.overflowY)
          if (scrollable && node.scrollHeight > node.clientHeight + 1) break
          node = node.parentElement
        }
        if (!node) return { found: false, tag: '', scrollTop: 0 }
        node.scrollTop = 400
        return {
          found: true,
          tag: node.tagName + '.' + (node.className || '').split(' ')[0],
          scrollTop: node.scrollTop,
        }
      })
      expect(metrics.found, 'picker must have a scrollable host').toBeTruthy()
      expect(metrics.scrollTop, 'scrolling the host must move scrollTop').toBeGreaterThan(0)
    } else {
      test.info().annotations.push({
        type: 'skipped-check',
        description: `scroll check needs more than 10 open findings, tenant has ${findingCount}`,
      })
    }

    // Link a finding that is not linked yet, then unlink it, and confirm its
    // checkbox flips each time (Check icon appears, then goes). An unlinked
    // row is used because a task keeps at least one finding: unlinking the
    // last one is refused (an empty finding_ids filter is not a scope).
    const unlinked = findingRows.filter({ hasNot: page.locator('svg.lucide-check') })
    test.skip((await unlinked.count()) === 0, 'every listed finding is already linked')
    // Found again by its title, so a re-sort after linking cannot move the
    // test onto another row.
    const title = await unlinked.first().locator('span.text-sm').first().innerText()
    const finding = findingRows.filter({ hasText: title }).first()
    const isChecked = async () => (await finding.locator('svg.lucide-check').count()) > 0
    await finding.click()
    await expect.poll(isChecked).toBe(true)
    // Toggle back so the test leaves the task's links unchanged.
    await finding.click()
    await expect.poll(isChecked).toBe(false)

    // Leave the picker → back to task details.
    await drawer.getByRole('button', { name: 'Done' }).click()
    await expect(drawer.getByRole('heading', { name: /Linked findings/i })).toBeVisible()
    await expect(pickerHeading).toBeHidden()
  })
})
