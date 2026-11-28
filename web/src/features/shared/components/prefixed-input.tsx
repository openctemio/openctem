'use client'

import { forwardRef, type ComponentProps } from 'react'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'

export interface PrefixedInputProps extends ComponentProps<typeof Input> {
  /** Fixed text before the value, e.g. the site address before a web-address name. */
  prefix: string
}

/**
 * An input with fixed text in front of it ("app.example.com/" + the name).
 * The value is what the person types, so it keeps its room: the prefix gives
 * way first and ends in an ellipsis (whole in its title), and the input never
 * shrinks below a readable name. A field holding one needs a full row in a
 * field grid.
 */
export const PrefixedInput = forwardRef<HTMLInputElement, PrefixedInputProps>(
  function PrefixedInput({ prefix, className, ...props }, ref) {
    return (
      <div data-slot="prefixed-input" className="flex min-w-0">
        <span
          data-testid="slug-host-prefix"
          title={prefix}
          // flex: 0 9999 auto: natural width, but it shrinks before the input does.
          className="inline-flex min-w-[4ch] max-w-[60%] shrink-[9999] items-center rounded-s-md border border-e-0 bg-muted px-3 text-code text-muted-foreground"
        >
          {/* The ellipsis needs a block box: text directly in a flex box is cut without one. */}
          <span data-cut-tooltip className="truncate">
            {prefix}
          </span>
        </span>
        <Input
          ref={ref}
          {...props}
          className={cn('min-w-[min(100%,18ch)] flex-1 basis-[18ch] rounded-s-none', className)}
        />
      </div>
    )
  }
)
