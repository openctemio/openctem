/**
 * How `ActionMenu` shows itself on a phone (below 768 px), decided by fit, not
 * by the call site (web/docs/ui-style-contract.md, "Floating surfaces"): a
 * short menu that fits beside its trigger stays an anchored menu; a long one,
 * one with a submenu, or one that would not fit becomes the bottom sheet.
 *
 * The decision is pure (`choosePhonePresentation`); `measurePhoneFit` reads the
 * screen, the trigger and the label widths when the menu is about to open.
 */
import {
  FLOATING_COLLISION_PADDING,
  FLOATING_MENU_MAX_WIDTH,
  floatingPadding,
  measureFloatingEnvironment,
} from '@/components/ui/floating'

export type PhonePresentation = 'menu' | 'sheet'

/** More rows than this and the menu is a sheet. */
export const PHONE_MENU_MAX_ITEMS = 6

/** Geometry of the kit's anchored menu on a phone (dropdown-menu.tsx, action-menu.tsx). */
export const PHONE_MENU_METRICS = {
  /** Row height on a phone (touch target). */
  row: 44,
  /** Vertical padding of a row (py-1.5). */
  rowPadY: 12,
  /** Line height of a label (text-body 14/20). */
  line: 20,
  /** Line height of an unavailable item's reason (text-cap 12/16). */
  reasonLine: 16,
  /** Group heading (px-2 py-1.5, 20 px line). */
  heading: 32,
  /** Divider between groups (h-px my-1). */
  separator: 9,
  /** Panel padding (p-1) plus border, top and bottom together. */
  panelY: 10,
  /** Panel padding plus border plus row padding, left and right together. */
  chromeX: 26,
  /** Icon plus gap, when the menu shows icons. */
  icon: 24,
  /** Gap between the trigger and the menu (sideOffset). */
  offset: 4,
  /** Labels wrap to at most this many lines in a menu. */
  maxLines: 2,
} as const

export type PhoneMenuShape = {
  /** One entry per item: single-line widths in px of its label and reason. */
  rows: { label: number; reason?: number }[]
  headings: number
  separators: number
  hasSubmenu: boolean
  /** The menu holds a text field (search, quick form). */
  hasInput: boolean
  icons: boolean
}

export type PhoneMenuSpace = {
  viewportWidth: number
  /** Room for the menu below the trigger, gutter and fixed bottom rows taken off. */
  below: number
  /** Room above the trigger, gutter taken off. */
  above: number
}

type CountShape = { rows: readonly unknown[]; headings: number }

/** Items counted against the limit: every row, and every heading after the first. */
export function countedItems(shape: CountShape): number {
  return shape.rows.length + Math.max(0, shape.headings - 1)
}

/** Decided from the item model alone: true when only measuring can still rule the menu out. */
export function mayBeAnchoredOnPhone(
  shape: CountShape & Pick<PhoneMenuShape, 'hasSubmenu' | 'hasInput'>
): boolean {
  return !shape.hasSubmenu && !shape.hasInput && countedItems(shape) <= PHONE_MENU_MAX_ITEMS
}

/** Widest a menu can be on this screen: 360 px, or the screen less both gutters. */
function menuWidth(viewportWidth: number): number {
  return Math.min(FLOATING_MENU_MAX_WIDTH, viewportWidth - 2 * FLOATING_COLLISION_PADDING)
}

function lines(width: number, room: number): number {
  return Math.max(1, Math.ceil(width / room))
}

/** Height of the anchored menu, or null when a label or reason needs more than two lines. */
export function phoneMenuHeight(shape: PhoneMenuShape, viewportWidth: number): number | null {
  const m = PHONE_MENU_METRICS
  const textRoom = menuWidth(viewportWidth) - m.chromeX - (shape.icons ? m.icon : 0)
  if (textRoom <= 0) return null
  let height = m.panelY + shape.headings * m.heading + shape.separators * m.separator
  for (const row of shape.rows) {
    const labelLines = lines(row.label, textRoom)
    const reasonLines = row.reason === undefined ? 0 : lines(row.reason, textRoom)
    if (labelLines > m.maxLines || reasonLines > m.maxLines) return null
    height += Math.max(m.row, m.rowPadY + labelLines * m.line + reasonLines * m.reasonLine)
  }
  return height
}

/**
 * Anchored menu when the menu has at most six items, no submenu, no text
 * field, every label fits in two lines within the widest menu (360 px, or
 * the screen less both gutters), and the whole menu fits below or above its trigger without scrolling.
 * Otherwise the bottom sheet.
 */
export function choosePhonePresentation(
  shape: PhoneMenuShape,
  space: PhoneMenuSpace
): PhonePresentation {
  if (!mayBeAnchoredOnPhone(shape)) return 'sheet'
  const height = phoneMenuHeight(shape, space.viewportWidth)
  if (height === null) return 'sheet'
  return height <= Math.max(space.below, space.above) ? 'menu' : 'sheet'
}

// ---------------------------------------------------------------------------
// Measuring (browser only)

let ctx: OffscreenCanvasRenderingContext2D | null | undefined

/** Width of one line of text, in px; an estimate where canvas text is missing (tests). */
export function textWidth(text: string, font: string, sizePx: number): number {
  if (ctx === undefined) {
    ctx = typeof OffscreenCanvas === 'function' ? new OffscreenCanvas(1, 1).getContext('2d') : null
  }
  if (!ctx) return text.length * sizePx * 0.6
  ctx.font = font
  // A pixel of slack per side for rounding and font hinting.
  return Math.ceil(ctx.measureText(text).width) + 2
}

/** Room around a trigger on the visible screen, as the menu's placement sees it. */
export function measurePhoneSpace(trigger: HTMLElement): PhoneMenuSpace {
  const r = trigger.getBoundingClientRect()
  const vv = window.visualViewport
  const top = vv ? vv.offsetTop : 0
  const bottom = vv ? vv.offsetTop + vv.height : window.innerHeight
  const pad = floatingPadding(FLOATING_COLLISION_PADDING, measureFloatingEnvironment())
  const off = PHONE_MENU_METRICS.offset
  return {
    viewportWidth: window.innerWidth,
    below: bottom - r.bottom - off - pad.bottom,
    above: r.top - top - off - pad.top,
  }
}

export type PhoneMenuModel = {
  rows: { label: string; reason?: string }[]
  headings: string[]
  separators: number
  hasSubmenu: boolean
  hasInput: boolean
  icons: boolean
}

/** Measures the labels in the trigger's font and decides. */
export function measurePhoneFit(trigger: HTMLElement, model: PhoneMenuModel): PhonePresentation {
  const family = getComputedStyle(trigger).fontFamily || 'sans-serif'
  const body = `400 14px ${family}`
  const strong = `500 14px ${family}`
  const cap = `400 12px ${family}`
  const shape: PhoneMenuShape = {
    rows: model.rows.map((row) => ({
      label: textWidth(row.label, body, 14),
      reason: row.reason === undefined ? undefined : textWidth(row.reason, cap, 12),
    })),
    headings: model.headings.length,
    separators: model.separators,
    hasSubmenu: model.hasSubmenu,
    hasInput: model.hasInput,
    icons: model.icons,
  }
  // Headings are short; one that would wrap beyond two lines rules the menu out too.
  const room = menuWidth(window.innerWidth) - PHONE_MENU_METRICS.chromeX
  for (const h of model.headings) {
    if (textWidth(h, strong, 14) > room * PHONE_MENU_METRICS.maxLines) return 'sheet'
  }
  return choosePhonePresentation(shape, measurePhoneSpace(trigger))
}
