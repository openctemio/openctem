/**
 * A row's name may end in an ellipsis (its column is the one kind allowed to);
 * its full text must then be reachable. These helpers give a name cell, or the
 * phone card's title, its text as the title while a part of it is cut, and take
 * that title away once it fits again. A title the page set itself is kept.
 * The layout matrix's cutMeaning check fails a cut name with no title.
 */

/** Boxes that end in an ellipsis or a line clamp. */
const CUT_SELECTOR = '.truncate, .text-ellipsis, [class*="line-clamp-"]'

/** True when the element, or a box in it, cuts its text. */
export function isTextCut(el: HTMLElement): boolean {
  const boxes = [el, ...Array.from(el.querySelectorAll<HTMLElement>(CUT_SELECTOR))]
  return boxes.some(
    (b) =>
      b.matches(CUT_SELECTOR) &&
      (b.scrollWidth > b.clientWidth + 1 || b.scrollHeight > b.clientHeight + 1)
  )
}

/** Sets (or removes) the element's own title from its text, by `cut`. */
export function syncCutTitle(el: HTMLElement, cut: boolean) {
  if (cut && !el.title) {
    el.title = (el.textContent ?? '').replace(/\s+/g, ' ').trim()
    el.dataset.autoTitle = ''
  } else if (!cut && el.dataset.autoTitle !== undefined) {
    el.removeAttribute('title')
    delete el.dataset.autoTitle
  }
}
