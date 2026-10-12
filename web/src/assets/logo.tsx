import { type SVGProps } from 'react'
import { cn } from '@/lib/utils'

/**
 * OpenCTEM mark — letterform direction (the chunky C with five notches).
 *
 * The mark is a stylised lowercase "c" built from five distinct arc segments,
 * one per CTEM stage (Scoping, Discovery, Prioritization, Validation,
 * Mobilization). The opening of the C contains a marker dot — the only
 * element that takes the accent colour.
 *
 * Design rationale and alternative directions are documented in
 * `docs/brand/README.md`. The geometry is locked: edit the SVG file there,
 * not this component.
 *
 * Behaviour:
 *   - Uses `currentColor` for all strokes, so it inherits whatever text
 *     colour the parent sets. Drop it into a dark sidebar, a light header,
 *     a print stylesheet — it just works.
 *   - The marker dot defaults to teal-600 (`#0D9488`) but accepts a
 *     `markerColor` prop for special contexts (e.g. brighter teal on dark).
 *   - Default size matches shadcn/ui icons (`size-6` = 24px).
 */
interface LogoProps extends SVGProps<SVGSVGElement> {
  /** Accent colour for the marker dot. Defaults to teal-600. */
  markerColor?: string
}

export function Logo({ className, markerColor = '#0D9488', ...props }: LogoProps) {
  // Canonical mark — exact spec from docs/brand/mark-letterform.svg.
  // Single smooth arc, 64° opening on the right, butt linecaps, marker
  // dot inside the opening. Do NOT modify this geometry without also
  // updating the brand asset; they are intentionally identical.
  return (
    <svg
      viewBox="0 0 120 120"
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      stroke="currentColor"
      strokeWidth="16"
      strokeLinecap="butt"
      className={cn('size-6', className)}
      role="img"
      aria-label="OpenCTEM"
      {...props}
    >
      <path d="M 92.22 39.86 A 38 38 0 1 0 92.22 80.14" />
      <circle cx="98" cy="60" r="7" fill={markerColor} stroke="none" />
    </svg>
  )
}

// Glyph outlines of the wordmark letters, set in Inter Bold (SIL Open Font
// Licence 1.1) at 56 units with -2.5 tracking on a y=66 baseline. They are
// paths, not <text>, so the lockup renders identically on every machine:
// a <text> element falls back to whatever font the OS has installed, and on
// a Linux desktop without the requested fonts the letters came out wider
// and ran into the C.
const WORDMARK_OPEN =
  'M19 66.6Q14.4 66.6 11 64.6Q7.6 62.6 5.8 59.1Q4 55.6 4 50.9Q4 46.1 5.8 42.6Q7.6 39 11 37Q14.4 35 19 35Q23.6 35 26.9 37Q30.3 39 32.1 42.6Q33.9 46.1 33.9 50.9Q33.9 55.6 32.1 59.1Q30.3 62.6 26.9 64.6Q23.6 66.6 19 66.6ZM19 60.1Q21.1 60.1 22.6 58.9Q24.1 57.7 24.8 55.6Q25.6 53.5 25.6 50.8Q25.6 48.1 24.8 46Q24.1 43.9 22.6 42.7Q21.1 41.5 19 41.5Q16.8 41.5 15.3 42.7Q13.8 43.9 13.1 46Q12.4 48.1 12.4 50.8Q12.4 53.5 13.1 55.6Q13.8 57.7 15.3 58.9Q16.8 60.1 19 60.1ZM37.1 77.4V35.4H45.2V40.6H45.6Q46.2 39.4 47.2 38.1Q48.3 36.8 50 35.9Q51.7 35 54.3 35Q57.7 35 60.5 36.8Q63.3 38.5 65 42Q66.7 45.5 66.7 50.8Q66.7 55.9 65.1 59.4Q63.4 62.9 60.6 64.7Q57.8 66.5 54.3 66.5Q51.8 66.5 50 65.7Q48.3 64.8 47.2 63.6Q46.2 62.3 45.6 61.1H45.3V77.4ZM51.7 59.9Q53.9 59.9 55.3 58.8Q56.8 57.6 57.5 55.5Q58.3 53.4 58.3 50.7Q58.3 48.1 57.5 46Q56.8 44 55.3 42.8Q53.9 41.6 51.7 41.6Q49.6 41.6 48.2 42.7Q46.7 43.9 45.9 45.9Q45.1 48 45.1 50.7Q45.1 53.5 45.9 55.6Q46.7 57.6 48.2 58.8Q49.7 59.9 51.7 59.9ZM83.7 66.6Q79.1 66.6 75.7 64.7Q72.3 62.8 70.5 59.2Q68.6 55.7 68.6 50.9Q68.6 46.1 70.5 42.6Q72.3 39 75.6 37Q78.9 35 83.3 35Q86.3 35 88.9 36Q91.5 37 93.5 38.9Q95.5 40.8 96.6 43.7Q97.7 46.6 97.7 50.6V52.8H72V47.7H93.7L89.8 49.1Q89.8 46.7 89.1 44.9Q88.4 43.2 87 42.2Q85.5 41.2 83.4 41.2Q81.3 41.2 79.8 42.2Q78.3 43.2 77.5 44.9Q76.8 46.6 76.8 48.7V52.4Q76.8 55 77.7 56.8Q78.5 58.6 80.1 59.5Q81.7 60.4 83.9 60.4Q85.3 60.4 86.5 60Q87.7 59.6 88.5 58.8Q89.3 58 89.8 56.8L97.2 58.2Q96.5 60.7 94.7 62.6Q92.8 64.5 90.1 65.6Q87.3 66.6 83.7 66.6ZM109 48.3V66H100.8V35.4H108.5L108.7 43.1H108.2Q109.4 39.2 111.8 37.1Q114.3 35 118.2 35Q121.3 35 123.7 36.4Q126.1 37.8 127.4 40.4Q128.7 43 128.7 46.6V66H120.5V48Q120.5 45.1 119 43.5Q117.5 41.9 114.9 41.9Q113.2 41.9 111.9 42.7Q110.5 43.4 109.7 44.8Q109 46.3 109 48.3Z'
const WORDMARK_TEM =
  'M222.5 35.4V41.7H204.3V35.4ZM208.6 28.2H216.8V57.1Q216.8 58.5 217.4 59.2Q218 59.9 219.6 59.9Q220 59.9 220.9 59.8Q221.7 59.7 222.1 59.5L223.3 65.7Q222 66.1 220.6 66.3Q219.2 66.4 218 66.4Q213.4 66.4 211 64.2Q208.6 62 208.6 57.8ZM239.1 66.6Q234.4 66.6 231.1 64.7Q227.7 62.8 225.8 59.2Q224 55.7 224 50.9Q224 46.1 225.8 42.6Q227.6 39 230.9 37Q234.2 35 238.7 35Q241.7 35 244.3 36Q246.9 37 248.9 38.9Q250.8 40.8 252 43.7Q253.1 46.6 253.1 50.6V52.8H227.4V47.7H249L245.2 49.1Q245.2 46.7 244.5 44.9Q243.8 43.2 242.3 42.2Q240.9 41.2 238.8 41.2Q236.7 41.2 235.2 42.2Q233.7 43.2 232.9 44.9Q232.1 46.6 232.1 48.7V52.4Q232.1 55 233 56.8Q233.9 58.6 235.5 59.5Q237.1 60.4 239.3 60.4Q240.7 60.4 241.9 60Q243.1 59.6 243.9 58.8Q244.7 58 245.2 56.8L252.6 58.2Q251.9 60.7 250 62.6Q248.2 64.5 245.4 65.6Q242.7 66.6 239.1 66.6ZM256.2 66V35.4H263.8L264.2 43H263.6Q264.3 40.2 265.7 38.4Q267.1 36.7 268.9 35.8Q270.8 35 272.8 35Q276.1 35 278.2 37.1Q280.2 39.1 281.1 43.5H280.2Q280.9 40.6 282.4 38.7Q283.9 36.8 286.1 35.9Q288.2 35 290.5 35Q293.3 35 295.5 36.2Q297.7 37.4 299 39.7Q300.3 42 300.3 45.4V66H292.1V46.9Q292.1 44.3 290.7 43.1Q289.3 41.8 287.2 41.8Q285.7 41.8 284.5 42.5Q283.4 43.2 282.8 44.4Q282.2 45.6 282.2 47.2V66H274.2V46.7Q274.2 44.5 272.9 43.2Q271.6 41.8 269.5 41.8Q268 41.8 266.9 42.5Q265.7 43.1 265 44.4Q264.4 45.7 264.4 47.5V66Z'

/**
 * OpenCTEM full logo: mark + wordmark on one line.
 *
 * The C in `openctem` IS the mark. Removing the C breaks the wordmark;
 * removing the wordmark leaves a recognisable brand letter.
 *
 * Use this in headers, login screens, legal pages: anywhere a horizontal
 * logo lockup belongs. For a collapsed sidebar or favicon, use `<Logo />`.
 *
 * Every element is a path or a shape; nothing depends on installed fonts.
 */
export function LogoFull({ className, markerColor = '#0D9488', ...props }: LogoProps) {
  // Geometry budget (viewBox 304x92, in viewBox units, measured on the ink):
  //   x=4      "open" left edge
  //   x=128.6  end of "open"
  //   x=134.6  visual left of the C (6 unit gap)
  //   x=198.3  visual right of the C, marker included
  //   x=204.3  start of "tem" (6 unit gap)
  //   x=300.3  end of "tem"
  // The C body reaches y=90.2, so the box is 92 high (88 clipped it).
  return (
    <svg
      viewBox="0 0 304 92"
      xmlns="http://www.w3.org/2000/svg"
      className={cn('h-7 w-auto', className)}
      role="img"
      aria-label="OpenCTEM"
      {...props}
    >
      <path data-testid="wordmark-open" d={WORDMARK_OPEN} fill="currentColor" />

      {/*
        The chunky C: the <Logo /> geometry scaled to 0.70 so its body sits
        on the wordmark. The marker dot is the only accent-coloured element.
      */}
      <g
        transform="translate(124.85 16) scale(0.70)"
        fill="none"
        stroke="currentColor"
        strokeWidth="16"
        strokeLinecap="butt"
      >
        <path d="M 92.22 39.86 A 38 38 0 1 0 92.22 80.14" />
        <circle cx="98" cy="60" r="7" fill={markerColor} stroke="none" />
      </g>

      <path data-testid="wordmark-tem" d={WORDMARK_TEM} fill="currentColor" />
    </svg>
  )
}
