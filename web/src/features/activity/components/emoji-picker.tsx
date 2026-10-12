'use client'

/**
 * The reaction emoji picker: frimousse (headless, virtualised, keyboard
 * navigable; about 12 kB gzipped), loaded only when a picker opens
 * (`reaction-picker.tsx` imports this file lazily).
 *
 * Emoji data is served by this app (`src/app/emojibase/…`), never fetched from
 * a CDN: the production CSP allows `connect-src 'self'` only, and a CDN would
 * learn who opens a picker.
 */

import { EmojiPicker as Picker } from 'frimousse'
import { cn } from '@/lib/utils'

export interface EmojiPickerProps {
  onSelect: (emoji: string) => void
  /** The viewer's most used emoji, shown first. */
  frequent?: string[]
  className?: string
}

export const EMOJIBASE_URL = '/emojibase'

export default function EmojiPicker({ onSelect, frequent = [], className }: EmojiPickerProps) {
  return (
    <Picker.Root
      className={cn('isolate flex h-[22rem] w-[19rem] flex-col bg-popover', className)}
      onEmojiSelect={({ emoji }) => onSelect(emoji)}
      emojibaseUrl={EMOJIBASE_URL}
      columns={8}
    >
      <div className="flex items-center gap-1.5 p-2 pb-1">
        <Picker.Search
          aria-label="Search emoji"
          placeholder="Search emoji"
          className="h-8 min-w-0 flex-1 rounded-md border bg-background px-2.5 text-sm outline-none placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring"
        />
        <Picker.SkinToneSelector
          aria-label="Change skin tone"
          title="Skin tone"
          className="flex size-8 shrink-0 items-center justify-center rounded-md border text-base hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        />
      </div>
      {frequent.length > 0 && (
        <div className="px-2 pb-1">
          <p className="px-1 pb-1 text-xs font-medium text-muted-foreground">Frequently used</p>
          <div role="group" aria-label="Frequently used" className="grid grid-cols-8">
            {frequent.map((e) => (
              <button
                key={e}
                type="button"
                aria-label={e}
                onClick={() => onSelect(e)}
                className="flex size-8 items-center justify-center rounded-md text-lg hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              >
                {e}
              </button>
            ))}
          </div>
        </div>
      )}
      <Picker.Viewport className="relative flex-1 outline-hidden">
        <Picker.Loading className="absolute inset-0 flex items-center justify-center text-sm text-muted-foreground">
          Loading…
        </Picker.Loading>
        <Picker.Empty className="absolute inset-0 flex items-center justify-center text-sm text-muted-foreground">
          No emoji found.
        </Picker.Empty>
        <Picker.List
          className="pb-1.5 select-none"
          components={{
            CategoryHeader: ({ category, ...props }) => (
              <div
                className="bg-popover px-3 pt-2 pb-1 text-xs font-medium text-muted-foreground"
                {...props}
              >
                {category.label}
              </div>
            ),
            Row: ({ children, ...props }) => (
              <div className="scroll-my-1.5 px-1.5" {...props}>
                {children}
              </div>
            ),
            Emoji: ({ emoji, ...props }) => (
              <button
                className={cn(
                  'flex size-8 items-center justify-center rounded-md text-lg',
                  emoji.isActive && 'bg-accent'
                )}
                {...props}
              >
                {emoji.emoji}
              </button>
            ),
          }}
        />
      </Picker.Viewport>
      <div className="flex h-9 shrink-0 items-center gap-2 border-t px-3 text-xs text-muted-foreground">
        <Picker.ActiveEmoji>
          {({ emoji }) =>
            emoji ? (
              <>
                <span className="text-lg">{emoji.emoji}</span>
                <span className="truncate">{emoji.label}</span>
              </>
            ) : (
              <span>Pick a reaction</span>
            )
          }
        </Picker.ActiveEmoji>
      </div>
    </Picker.Root>
  )
}
