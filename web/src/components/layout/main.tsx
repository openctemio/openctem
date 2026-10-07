/**
 * Main Content Wrapper Component
 *
 * Generic main content container with flexible layout options
 * - Supports fixed and fluid layouts
 * - Handles overflow and flex-grow
 * - Can be used across different routes
 *
 * A page has exactly one `main` landmark. Layouts that already render it
 * (the dashboard shell, through <MainRegion>) tell <Main> so through context,
 * and <Main> then renders a plain <div>. Outside such a layout (auth pages,
 * the admin console, onboarding) <Main> is the landmark itself.
 */

'use client'

import {
  createContext,
  forwardRef,
  useContext,
  useImperativeHandle,
  useRef,
  type HTMLAttributes,
  type Ref,
} from 'react'
import { useScrollActivity } from '@/hooks/use-scroll-activity'
import { cn } from '@/lib/utils'

const InsideMainLandmark = createContext(false)

interface MainProps extends HTMLAttributes<HTMLElement> {
  /**
   * Whether the main content should have fixed height
   * @default false
   */
  fixed?: boolean

  /**
   * Whether to use full width (no max-width constraint)
   * @default false
   */
  fluid?: boolean
}

export const Main = forwardRef<HTMLElement, MainProps>(
  ({ fixed, className, fluid, ...props }, ref) => {
    const nested = useContext(InsideMainLandmark)
    const Tag = nested ? 'div' : 'main'
    const content = (
      <Tag
        ref={ref as Ref<HTMLDivElement>}
        data-layout={fixed ? 'fixed' : 'auto'}
        className={cn(
          // overflow-x: clip, not hidden — hidden forces overflow-y to auto,
          // which made <Main> a (never-scrolling) scroll container and broke
          // position: sticky for everything inside a page.
          'px-4 py-6 overflow-x-clip sm:px-6 lg:px-8',
          fixed && 'flex flex-col flex-grow overflow-hidden',
          !fluid && 'w-full mx-auto',
          className
        )}
        {...props}
      />
    )
    // A <Main> that is the landmark makes everything inside it "nested".
    return nested ? (
      content
    ) : (
      <InsideMainLandmark.Provider value={true}>{content}</InsideMainLandmark.Provider>
    )
  }
)

Main.displayName = 'Main'

/**
 * The layout-level `main` landmark and skip-link target (`#content`).
 * Every <Main> rendered inside it is a plain container.
 *
 * It is the app's page scroller: its scrollbar gutter is always reserved, so
 * content never shifts when a page grows long enough to scroll, and the thumb
 * shows only while scrolling (`scrollbar-auto-hide`).
 */
export const MainRegion = forwardRef<HTMLElement, HTMLAttributes<HTMLElement>>(
  ({ id = 'content', className, ...props }, ref) => {
    const innerRef = useRef<HTMLElement>(null)
    useImperativeHandle(ref, () => innerRef.current as HTMLElement)
    useScrollActivity(innerRef)
    return (
      <InsideMainLandmark.Provider value={true}>
        <main ref={innerRef} id={id} className={cn('scrollbar-auto-hide', className)} {...props} />
      </InsideMainLandmark.Provider>
    )
  }
)

MainRegion.displayName = 'MainRegion'
