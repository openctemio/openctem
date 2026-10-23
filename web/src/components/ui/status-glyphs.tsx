import type { ComponentType } from 'react'

/**
 * Status progression glyphs: dashed circle (untouched), ring with dot (open),
 * half and three-quarter circle (in progress, fix applied), filled check
 * (resolved), slashed circle (closed without a fix). Static shapes: nothing
 * spins. Decorative: the label beside them carries the meaning.
 */
export type StatusGlyph = ComponentType<{ className?: string }>

const base = {
  'aria-hidden': true,
  focusable: 'false' as const,
  viewBox: '0 0 12 12',
  fill: 'none',
}

export const DashedCircleGlyph: StatusGlyph = ({ className }) => (
  <svg {...base} className={className}>
    <circle cx="6" cy="6" r="4.5" stroke="currentColor" strokeWidth="1.4" strokeDasharray="2 2" />
  </svg>
)

export const RingDotGlyph: StatusGlyph = ({ className }) => (
  <svg {...base} className={className}>
    <circle cx="6" cy="6" r="4.6" stroke="currentColor" strokeWidth="1.4" />
    <circle cx="6" cy="6" r="1.6" fill="currentColor" />
  </svg>
)

export const HalfCircleGlyph: StatusGlyph = ({ className }) => (
  <svg {...base} className={className}>
    <circle cx="6" cy="6" r="4.6" stroke="currentColor" strokeWidth="1.4" />
    <path d="M6 3a3 3 0 0 1 0 6z" fill="currentColor" />
  </svg>
)

export const ThreeQuarterCircleGlyph: StatusGlyph = ({ className }) => (
  <svg {...base} className={className}>
    <circle cx="6" cy="6" r="4.6" stroke="currentColor" strokeWidth="1.4" />
    <path d="M6 6V3a3 3 0 1 1-3 3z" fill="currentColor" />
  </svg>
)

export const CheckCircleGlyph: StatusGlyph = ({ className }) => (
  <svg {...base} className={className}>
    <circle cx="6" cy="6" r="5.3" fill="currentColor" />
    <path
      d="M3.7 6.2l1.7 1.7 3-3.4"
      stroke="var(--background)"
      strokeWidth="1.4"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
)

export const SlashedCircleGlyph: StatusGlyph = ({ className }) => (
  <svg {...base} className={className}>
    <circle cx="6" cy="6" r="4.6" stroke="currentColor" strokeWidth="1.4" />
    <path d="M2.8 9.2l6.4-6.4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
  </svg>
)
