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
// Licence 1.1) at 56 units with -2.5 tracking on a y=45.4 baseline. They are
// paths, not <text>, so the lockup renders identically on every machine:
// a <text> element falls back to whatever font the OS has installed, and on
// a Linux desktop without the requested fonts the letters came out wider
// and ran into the C.
const WORDMARK_OPEN =
  'M19 46Q14.4 46 11 44Q7.6 42 5.8 38.5Q4 35 4 30.3Q4 25.5 5.8 22Q7.6 18.4 11 16.4Q14.4 14.4 19 14.4Q23.6 14.4 26.9 16.4Q30.3 18.4 32.1 22Q33.9 25.5 33.9 30.3Q33.9 35 32.1 38.5Q30.3 42 26.9 44Q23.6 46 19 46ZM19 39.5Q21.1 39.5 22.6 38.3Q24.1 37.1 24.8 35Q25.6 32.9 25.6 30.2Q25.6 27.5 24.8 25.4Q24.1 23.3 22.6 22.1Q21.1 20.9 19 20.9Q16.8 20.9 15.3 22.1Q13.8 23.3 13.1 25.4Q12.4 27.5 12.4 30.2Q12.4 32.9 13.1 35Q13.8 37.1 15.3 38.3Q16.8 39.5 19 39.5ZM37.1 56.8V14.8H45.2V20H45.6Q46.2 18.8 47.2 17.5Q48.3 16.2 50 15.3Q51.7 14.4 54.3 14.4Q57.7 14.4 60.5 16.2Q63.3 17.9 65 21.4Q66.7 24.9 66.7 30.2Q66.7 35.3 65.1 38.8Q63.4 42.3 60.6 44.1Q57.8 45.9 54.3 45.9Q51.8 45.9 50 45.1Q48.3 44.2 47.2 43Q46.2 41.7 45.6 40.5H45.3V56.8ZM51.7 39.3Q53.9 39.3 55.3 38.2Q56.8 37 57.5 34.9Q58.3 32.8 58.3 30.1Q58.3 27.5 57.5 25.4Q56.8 23.4 55.3 22.2Q53.9 21 51.7 21Q49.6 21 48.2 22.1Q46.7 23.3 45.9 25.3Q45.1 27.4 45.1 30.1Q45.1 32.9 45.9 35Q46.7 37 48.2 38.2Q49.7 39.3 51.7 39.3ZM83.7 46Q79.1 46 75.7 44.1Q72.3 42.2 70.5 38.6Q68.6 35.1 68.6 30.3Q68.6 25.5 70.5 22Q72.3 18.4 75.6 16.4Q78.9 14.4 83.3 14.4Q86.3 14.4 88.9 15.4Q91.5 16.4 93.5 18.3Q95.5 20.2 96.6 23.1Q97.7 26 97.7 30V32.2H72V27.1H93.7L89.8 28.5Q89.8 26.1 89.1 24.3Q88.4 22.6 87 21.6Q85.5 20.6 83.4 20.6Q81.3 20.6 79.8 21.6Q78.3 22.6 77.5 24.3Q76.8 26 76.8 28.1V31.8Q76.8 34.4 77.7 36.2Q78.5 38 80.1 38.9Q81.7 39.8 83.9 39.8Q85.3 39.8 86.5 39.4Q87.7 39 88.5 38.2Q89.3 37.4 89.8 36.2L97.2 37.6Q96.5 40.1 94.7 42Q92.8 43.9 90.1 45Q87.3 46 83.7 46ZM109 27.7V45.4H100.8V14.8H108.5L108.7 22.5H108.2Q109.4 18.6 111.8 16.5Q114.3 14.4 118.2 14.4Q121.3 14.4 123.7 15.8Q126.1 17.2 127.4 19.8Q128.7 22.4 128.7 26V45.4H120.5V27.4Q120.5 24.5 119 22.9Q117.5 21.3 114.9 21.3Q113.2 21.3 111.9 22.1Q110.5 22.8 109.7 24.2Q109 25.7 109 27.7Z'
const WORDMARK_TEM =
  'M196.05 14.8V21.1H177.85V14.8ZM182.15 7.6H190.35V36.5Q190.35 37.9 190.95 38.6Q191.55 39.3 193.15 39.3Q193.55 39.3 194.45 39.2Q195.25 39.1 195.65 38.9L196.85 45.1Q195.55 45.5 194.15 45.7Q192.75 45.8 191.55 45.8Q186.95 45.8 184.55 43.6Q182.15 41.4 182.15 37.2ZM212.65 46Q207.95 46 204.65 44.1Q201.25 42.2 199.35 38.6Q197.55 35.1 197.55 30.3Q197.55 25.5 199.35 22Q201.15 18.4 204.45 16.4Q207.75 14.4 212.25 14.4Q215.25 14.4 217.85 15.4Q220.45 16.4 222.45 18.3Q224.35 20.2 225.55 23.1Q226.65 26 226.65 30V32.2H200.95V27.1H222.55L218.75 28.5Q218.75 26.1 218.05 24.3Q217.35 22.6 215.85 21.6Q214.45 20.6 212.35 20.6Q210.25 20.6 208.75 21.6Q207.25 22.6 206.45 24.3Q205.65 26 205.65 28.1V31.8Q205.65 34.4 206.55 36.2Q207.45 38 209.05 38.9Q210.65 39.8 212.85 39.8Q214.25 39.8 215.45 39.4Q216.65 39 217.45 38.2Q218.25 37.4 218.75 36.2L226.15 37.6Q225.45 40.1 223.55 42Q221.75 43.9 218.95 45Q216.25 46 212.65 46ZM229.75 45.4V14.8H237.35L237.75 22.4H237.15Q237.85 19.6 239.25 17.8Q240.65 16.1 242.45 15.2Q244.35 14.4 246.35 14.4Q249.65 14.4 251.75 16.5Q253.75 18.5 254.65 22.9H253.75Q254.45 20 255.95 18.1Q257.45 16.2 259.65 15.3Q261.75 14.4 264.05 14.4Q266.85 14.4 269.05 15.6Q271.25 16.8 272.55 19.1Q273.85 21.4 273.85 24.8V45.4H265.65V26.3Q265.65 23.7 264.25 22.5Q262.85 21.2 260.75 21.2Q259.25 21.2 258.05 21.9Q256.95 22.6 256.35 23.8Q255.75 25 255.75 26.6V45.4H247.75V26.1Q247.75 23.9 246.45 22.6Q245.15 21.2 243.05 21.2Q241.55 21.2 240.45 21.9Q239.25 22.5 238.55 23.8Q237.95 25.1 237.95 26.9V45.4Z'

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
  // Type metrics (viewBox units): cap height y=4.7, x-height y=14.8,
  // baseline y=45.4, descender of the p y=56.8.
  //
  // The C is drawn as a capital of the wordmark: its outer edge runs from
  // y=4 to y=46.1, i.e. cap height to baseline plus the usual overshoot of
  // a round letter (about 1.5 percent) at both ends, and its stroke (8.8)
  // matches the weight of the round letters (the o is 8.4, the stems 8.2).
  // The arc keeps the mark's 64 degree opening and the marker sits on the
  // stroke's centre line in that opening, as in <Logo />.
  //
  // Horizontal budget, measured on the ink:
  //   x=4       "open" left edge
  //   x=128.7   end of "open" (straight stem of the n)
  //   x=132.3   left of the C (3.6, a straight-to-round gap of the font)
  //   x=173.85  right of the marker
  //   x=177.85  start of "tem" (4: the marker is the nearest ink to the t,
  //             so it gets a little more than the n side)
  //   x=273.85  end of "tem"
  // The box pads the ink by 4 on every side, so the lockup is centred in
  // its container and the box centre falls on the x-height band.
  return (
    <svg
      viewBox="0 0 278 61"
      xmlns="http://www.w3.org/2000/svg"
      className={cn('h-5 w-auto', className)}
      role="img"
      aria-label="OpenCTEM"
      {...props}
    >
      <path data-testid="wordmark-open" d={WORDMARK_OPEN} fill="currentColor" />
      <path
        data-testid="wordmark-c"
        d="M 167.47 16.23 A 16.65 16.65 0 1 0 167.47 33.87"
        fill="none"
        stroke="currentColor"
        strokeWidth="8.8"
        strokeLinecap="butt"
      />
      {/* The marker dot is the only accent-coloured element. */}
      <circle cx="170" cy="25.05" r="3.85" fill={markerColor} />
      <path data-testid="wordmark-tem" d={WORDMARK_TEM} fill="currentColor" />
    </svg>
  )
}
