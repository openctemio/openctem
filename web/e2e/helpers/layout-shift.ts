import type { Page } from '@playwright/test'

/**
 * Starts counting layout shifts (the CLS score: shifts not caused by input)
 * for the next navigation of `page`. Read the total with `layoutShift(page)`.
 */
export async function trackLayoutShift(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as { __layoutShift: number; __layoutShiftNodes: string[] }
    w.__layoutShift = 0
    w.__layoutShiftNodes = []
    try {
      new PerformanceObserver((list) => {
        for (const e of list.getEntries() as unknown as Array<{
          value: number
          hadRecentInput: boolean
          sources?: Array<{ node?: Node | null }>
        }>) {
          if (e.hadRecentInput) continue
          w.__layoutShift += e.value
          for (const s of e.sources ?? []) {
            const n = s.node as HTMLElement | null | undefined
            if (n?.nodeName)
              w.__layoutShiftNodes.push(`${n.nodeName}.${String(n.className).slice(0, 60)}`)
          }
        }
      }).observe({ type: 'layout-shift', buffered: true })
    } catch {
      // No layout-shift entries in this engine: the score stays 0.
    }
  })
}

/** The layout shift counted since `trackLayoutShift`, and the nodes that moved. */
export async function layoutShift(page: Page) {
  return page.evaluate(() => {
    const w = window as unknown as { __layoutShift?: number; __layoutShiftNodes?: string[] }
    return { score: w.__layoutShift ?? 0, nodes: (w.__layoutShiftNodes ?? []).slice(0, 10) }
  })
}
