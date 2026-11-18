'use client'

import * as React from 'react'
import { Button } from '@/components/ui/button'

/**
 * One filled button per screen. An empty state's action is filled only when
 * no other filled button is shown on the screen (the page's main action in its
 * header, most often); otherwise it is drawn as an outline button. A page
 * whose header has no main action in that state keeps the empty state's
 * action filled, so the screen still has one obvious next step.
 *
 * The check runs before paint and again when the page around it changes
 * (a header action that appears once permissions load). It reaches kit
 * `Button`s written in the action's own tree (directly or inside wrappers
 * such as `Can`); a filled button it cannot reach is reported by a warning
 * outside production builds.
 */

const FILLED_SELECTOR =
  '[data-slot=button][data-variant=default],[data-slot=button][data-variant=signal]'

/** Drawn and at least partly on the screen. */
function shownOnScreen(el: Element): boolean {
  if (el.getClientRects().length === 0) return false
  if (el.closest('[aria-hidden=true],[inert],[hidden]')) return false
  const box = el.getBoundingClientRect()
  return box.height > 0 && box.bottom > 0 && box.top < window.innerHeight
}

/** The filled buttons shown on the screen, outside `root` when given. */
export function shownFilledButtons(doc: Document, root?: Element): HTMLElement[] {
  return Array.from(doc.querySelectorAll<HTMLElement>(FILLED_SELECTOR)).filter(
    (el) => !(root && root.contains(el)) && shownOnScreen(el)
  )
}

function isFilledVariant(variant: unknown): boolean {
  return variant === undefined || variant === null || variant === 'default' || variant === 'signal'
}

/** The action tree with every filled kit Button drawn as an outline one. */
function subdue(node: React.ReactNode): React.ReactNode {
  return React.Children.map(node, (child) => {
    if (!React.isValidElement<{ variant?: unknown; children?: React.ReactNode }>(child)) {
      return child
    }
    if (child.type === Button) {
      return isFilledVariant(child.props.variant)
        ? React.cloneElement(child, { variant: 'outline' })
        : child
    }
    const inner = child.props.children
    if (inner === undefined || typeof inner === 'function') return child
    return React.cloneElement(child, undefined, subdue(inner))
  })
}

export function OneFilledAction({ children, ...props }: React.ComponentProps<'div'>) {
  const ref = React.useRef<HTMLDivElement>(null)
  const [subdued, setSubdued] = React.useState(false)

  React.useLayoutEffect(() => {
    const root = ref.current
    if (!root) return
    const check = () => setSubdued(shownFilledButtons(document, root).length > 0)
    check()
    const observer = new MutationObserver(check)
    observer.observe(document.body, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ['data-variant', 'hidden', 'aria-hidden'],
    })
    return () => observer.disconnect()
  }, [])

  React.useEffect(() => {
    if (process.env.NODE_ENV === 'production' || !subdued) return
    const root = ref.current
    if (!root) return
    const own = shownFilledButtons(document).filter((el) => root.contains(el))
    if (own.length > 0) {
      console.warn(
        `One filled button per screen: this empty state still shows a filled action (${own
          .map((el) => JSON.stringify(el.textContent?.trim() ?? ''))
          .join(
            ', '
          )}) beside another filled button. Pass a kit Button in its action tree so it is drawn as an outline button.`
      )
    }
  }, [subdued])

  return (
    <div ref={ref} {...props}>
      {subdued ? subdue(children) : children}
    </div>
  )
}
