/**
 * The classes of a text link (see `TextLink`). A plain module, not a client
 * one: a server component that draws its own `<a>` (the legal pages) imports
 * the classes from here, because a value imported from a `'use client'`
 * module reaches a server component as a client reference, not as the string.
 */
export const TEXT_LINK_CLASS = {
  inline:
    'text-signal-text underline decoration-signal-text/45 underline-offset-3 hover:decoration-current focus-visible:decoration-current',
  nav: 'underline-offset-3 hover:underline focus-visible:underline',
} as const
