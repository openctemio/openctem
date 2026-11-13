import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'

import { cn } from '@/lib/utils'

const buttonVariants = cva(
  "relative cursor-pointer inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md text-body font-medium transition-all disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 shrink-0 [&_svg]:shrink-0 outline-none max-md:text-dense max-md:before:absolute max-md:before:inset-x-0 max-md:before:top-1/2 max-md:before:h-touch-target max-md:before:-translate-y-1/2 focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive",
  {
    variants: {
      variant: {
        default: 'bg-primary text-primary-foreground shadow-xs hover:bg-primary/90',
        destructive:
          'bg-destructive text-destructive-foreground shadow-xs hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40',
        outline:
          'border bg-background shadow-xs hover:bg-accent hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50',
        secondary: 'bg-secondary text-secondary-foreground shadow-xs hover:bg-secondary/80',
        ghost: 'hover:bg-accent hover:text-accent-foreground dark:hover:bg-accent/50',
        // A standalone link: plain at rest, underlined on hover and focus.
        link: 'text-signal-text underline-offset-4 hover:underline focus-visible:underline',
      },
      // Control scale ("Sizes" in web/docs/ui-style-contract.md): 32 default;
      // sm and icon-sm 28 in a dense place (density.tsx), 32 elsewhere; lg 36
      // (entry pages); xs 24 (the info icon). Below 768px the live UI's
      // heights (36, sm 32, lg 40) with compact content (13px text, 10px
      // padding, 8 beside an icon) and an invisible touch target (::before):
      // 44px tall, the button's own width, so neighbours never share a hit
      // area and nothing reaches past the button's sides.
      size: {
        default:
          'h-control px-3 has-[>svg]:px-2.5 max-md:h-control-touch max-md:px-2.5 max-md:has-[>svg]:px-2',
        sm: 'h-control-dense px-2.5 has-[>svg]:px-2 max-md:h-control-touch-sm',
        lg: 'h-control-entry px-4 has-[>svg]:px-3 max-md:h-control-touch-lg max-md:px-2.5 max-md:has-[>svg]:px-2',
        icon: 'size-control max-md:size-control-touch',
        'icon-sm': 'size-control-dense max-md:size-control-touch-sm',
        xs: 'size-control-xs',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
)

/**
 * A button whose label shows only from a width up (`hidden sm:inline`,
 * `sr-only sm:not-sr-only`) is icon-only below it, and a square there.
 * An always icon-only button takes an icon size (icon, icon-sm, xs).
 * src/components/ui/__tests__/icon-button-guard.test.ts enforces both.
 */
const ICON_ONLY_BELOW = {
  sm: 'max-sm:aspect-square max-sm:px-0 max-sm:has-[>svg]:px-0',
  md: 'max-md:aspect-square max-md:px-0 max-md:has-[>svg]:px-0',
  lg: 'max-lg:aspect-square max-lg:px-0 max-lg:has-[>svg]:px-0',
  // The list toolbar's container (DataTable): the label shows from @2xl.
  '@2xl/toolbar':
    '@max-2xl/toolbar:aspect-square @max-2xl/toolbar:px-0 @max-2xl/toolbar:has-[>svg]:px-0',
} as const

function Button({
  className,
  variant,
  size,
  asChild = false,
  iconOnlyBelow,
  ...props
}: React.ComponentProps<'button'> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
    /** Icon-only below this breakpoint: drawn as a square there. */
    iconOnlyBelow?: keyof typeof ICON_ONLY_BELOW
  }) {
  const Comp = asChild ? Slot : 'button'

  return (
    <Comp
      data-slot="button"
      data-size={size ?? 'default'}
      className={cn(
        buttonVariants({ variant, size }),
        iconOnlyBelow && ICON_ONLY_BELOW[iconOnlyBelow],
        className
      )}
      {...props}
    />
  )
}

export { Button, buttonVariants }
