'use client'

/**
 * Lazy-loaded Recharts components
 *
 * These components dynamically import recharts to reduce initial bundle size.
 * Recharts is ~450KB uncompressed, so lazy loading improves initial page load.
 */

import { useEffect, useState, type ComponentProps, type ComponentType } from 'react'
import dynamic from 'next/dynamic'
import type {
  Area as RechartsArea,
  Bar as RechartsBar,
  CartesianGrid as RechartsCartesianGrid,
  Legend as RechartsLegend,
  Line as RechartsLine,
  Pie as RechartsPie,
  ReferenceLine as RechartsReferenceLine,
  Tooltip as RechartsTooltip,
  XAxis as RechartsXAxis,
  YAxis as RechartsYAxis,
} from 'recharts'
import { ChartSkeleton } from '@/components/ui/chart-skeleton'

type RechartsModule = typeof import('recharts')

/**
 * Nothing here may import recharts statically (only types): a static import pulls
 * the whole library into the first load of every page that shows a chart. The
 * module is fetched once on first use; every chart and every series wrapper
 * below reads it from this cache, so children render in the same pass as their
 * chart without a second round trip.
 */
let loadedRecharts: RechartsModule | null = null
function loadRecharts(): Promise<RechartsModule> {
  return import('recharts').then((mod) => {
    loadedRecharts = mod
    return mod
  })
}

/** A recharts part (series, axis, tooltip, ...) that renders once the module is loaded. */
function lazyPart<P>(name: keyof RechartsModule, displayName: string): ComponentType<P> {
  function LazyPart(props: P) {
    const [mod, setMod] = useState(loadedRecharts)
    useEffect(() => {
      if (!mod) {
        let live = true
        loadRecharts().then((m) => live && setMod(m))
        return () => {
          live = false
        }
      }
    }, [mod])
    if (!mod) return null
    const Part = mod[name] as unknown as ComponentType<P>
    return <Part {...(props as P & object)} />
  }
  LazyPart.displayName = displayName
  return LazyPart
}

// Lazy load the entire recharts library
const LazyAreaChart = dynamic(() => loadRecharts().then((mod) => ({ default: mod.AreaChart })), {
  loading: () => <ChartSkeleton type="area" />,
  ssr: false,
})

const LazyBarChart = dynamic(() => loadRecharts().then((mod) => ({ default: mod.BarChart })), {
  loading: () => <ChartSkeleton type="bar" />,
  ssr: false,
})

const LazyPieChart = dynamic(() => loadRecharts().then((mod) => ({ default: mod.PieChart })), {
  loading: () => <ChartSkeleton type="pie" />,
  ssr: false,
})

const LazyLineChart = dynamic(() => loadRecharts().then((mod) => ({ default: mod.LineChart })), {
  loading: () => <ChartSkeleton type="line" />,
  ssr: false,
})

/**
 * Charts follow a width change once it settles: longer than the sidebar's 250ms
 * open/collapse so a toggle costs one chart render, short enough that a window
 * resize still feels live.
 */
const CHART_RESIZE_THROTTLE_MS = 300

const LazyResponsiveContainer = dynamic(
  () =>
    loadRecharts().then((mod) => {
      // Wrap ResponsiveContainer with minWidth={0} to prevent
      // "width(-1) and height(-1) should be greater than 0" error
      // when the chart renders before its container is visible.
      //
      // debounce: resize at most once per CHART_RESIZE_THROTTLE_MS (trailing).
      // Without it every chart re-renders, and replays its draw animation, on
      // every frame the container width changes, e.g. the 250ms sidebar
      // open/collapse, which stalled the dashboard to a few frames.
      const Original = mod.ResponsiveContainer
      const Wrapped = (props: React.ComponentProps<typeof Original>) => (
        <Original minWidth={0} debounce={CHART_RESIZE_THROTTLE_MS} {...props} />
      )
      Wrapped.displayName = 'ResponsiveContainer'
      return { default: Wrapped }
    }),
  { ssr: false }
)

// Charts
export {
  LazyAreaChart as AreaChart,
  LazyBarChart as BarChart,
  LazyPieChart as PieChart,
  LazyLineChart as LineChart,
  LazyResponsiveContainer as ResponsiveContainer,
}

// Parts that sit inside a chart. Cell is only read by recharts' Pie/Bar through its
// displayName, so a stand-in with that name is enough and needs no library code.
export const Legend = lazyPart<ComponentProps<typeof RechartsLegend>>('Legend', 'Legend')
export const Tooltip = lazyPart<ComponentProps<typeof RechartsTooltip>>('Tooltip', 'Tooltip')
export const XAxis = lazyPart<ComponentProps<typeof RechartsXAxis>>('XAxis', 'XAxis')
export const YAxis = lazyPart<ComponentProps<typeof RechartsYAxis>>('YAxis', 'YAxis')
export const CartesianGrid = lazyPart<ComponentProps<typeof RechartsCartesianGrid>>(
  'CartesianGrid',
  'CartesianGrid'
)
export const ReferenceLine = lazyPart<ComponentProps<typeof RechartsReferenceLine>>(
  'ReferenceLine',
  'ReferenceLine'
)
export function Cell(_props: { fill?: string; stroke?: string; [key: string]: unknown }) {
  return null
}
Cell.displayName = 'Cell'

/**
 * Series draw-in only when the chart first appears. Recharts otherwise replays
 * the draw animation (1.5s by default, a re-render per frame) whenever the
 * points move, which includes every resize: collapsing the sidebar made each
 * dashboard chart re-animate and stalled the page. After the first draw a
 * series updates in place. A caller can still pass isAnimationActive.
 */
const FIRST_DRAW_MS = 800

function useFirstDrawOnly(): boolean {
  const [animate, setAnimate] = useState(true)
  useEffect(() => {
    const t = setTimeout(() => setAnimate(false), FIRST_DRAW_MS + 100)
    return () => clearTimeout(t)
  }, [])
  return animate
}

const LazyArea = lazyPart<ComponentProps<typeof RechartsArea>>('Area', 'Area')
function Area(props: ComponentProps<typeof RechartsArea>) {
  const animate = useFirstDrawOnly()
  return <LazyArea isAnimationActive={animate} animationDuration={FIRST_DRAW_MS} {...props} />
}
const LazyBar = lazyPart<ComponentProps<typeof RechartsBar>>('Bar', 'Bar')
function Bar(props: ComponentProps<typeof RechartsBar>) {
  const animate = useFirstDrawOnly()
  return <LazyBar isAnimationActive={animate} animationDuration={FIRST_DRAW_MS} {...props} />
}
const LazyLine = lazyPart<ComponentProps<typeof RechartsLine>>('Line', 'Line')
function Line(props: ComponentProps<typeof RechartsLine>) {
  const animate = useFirstDrawOnly()
  return <LazyLine isAnimationActive={animate} animationDuration={FIRST_DRAW_MS} {...props} />
}
const LazyPie = lazyPart<ComponentProps<typeof RechartsPie>>('Pie', 'Pie')
function Pie(props: ComponentProps<typeof RechartsPie>) {
  const animate = useFirstDrawOnly()
  return <LazyPie isAnimationActive={animate} animationDuration={FIRST_DRAW_MS} {...props} />
}
Area.displayName = 'Area'
Bar.displayName = 'Bar'
Line.displayName = 'Line'
Pie.displayName = 'Pie'

export { Area, Bar, Line, Pie }
