import type { Locator } from '@playwright/test'

/**
 * The height a finger can hit: below 768px a kit button is drawn at the live
 * UI's height (36, small 32) and carries an invisible 44px-tall touch target
 * (its ::before box; "Sizes" in web/docs/ui-style-contract.md). Returns the
 * larger of the drawn box and that target.
 */
export async function touchTargetHeight(control: Locator): Promise<number> {
  return control.evaluate((el) => {
    const drawn = el.getBoundingClientRect().height
    const target = parseFloat(getComputedStyle(el, '::before').height)
    return Math.max(drawn, Number.isFinite(target) ? target : 0)
  })
}
