'use client'

import * as React from 'react'
import { useTheme } from 'next-themes'
import { Toaster } from 'sonner'

/** Under Tailwind's `sm`: where dialogs are bottom sheets with a pinned footer. */
const PHONE_QUERY = '(max-width: 639px)'

function subscribe(onChange: () => void) {
  if (typeof window.matchMedia !== 'function') return () => {}
  const mql = window.matchMedia(PHONE_QUERY)
  mql.addEventListener('change', onChange)
  return () => mql.removeEventListener('change', onChange)
}

const isPhoneNow = () =>
  typeof window.matchMedia === 'function' && window.matchMedia(PHONE_QUERY).matches
const isPhoneOnServer = () => false

/**
 * Sonner's colours come from its own palette (white in both themes, its own
 * greens and reds for rich colours). These variables put every toast on the
 * brand tokens instead: a plain toast is a popover, a rich one uses the status
 * lozenge pair of its meaning (resolved, progress, accepted, danger), whose
 * text is AA on its tint in both themes (src/styles/__tests__/contrast.test.ts).
 */
export const TOAST_TOKENS = {
  '--normal-bg': 'var(--popover)',
  '--normal-text': 'var(--popover-foreground)',
  '--normal-border': 'var(--border)',
  '--success-bg': 'var(--st-resolved-bg)',
  '--success-text': 'var(--st-resolved-fg)',
  '--success-border': 'var(--st-resolved-border)',
  '--info-bg': 'var(--st-progress-bg)',
  '--info-text': 'var(--st-progress-fg)',
  '--info-border': 'var(--st-progress-border)',
  '--warning-bg': 'var(--st-accepted-bg)',
  '--warning-text': 'var(--st-accepted-fg)',
  '--warning-border': 'var(--st-accepted-border)',
  '--error-bg': 'var(--tone-danger-bg)',
  '--error-text': 'var(--tone-danger-fg)',
  '--error-border': 'var(--tone-danger-border)',
  '--border-radius': 'var(--radius)',
} as React.CSSProperties

/**
 * The app's toaster. Bottom right on larger screens; at the top on phones,
 * where a dialog is a bottom sheet whose footer (Create, Save) is pinned at
 * the bottom of the screen: a toast there would cover the very button the
 * user needs after an error. The top inset clears the notch.
 */
export function AppToaster() {
  const phone = React.useSyncExternalStore(subscribe, isPhoneNow, isPhoneOnServer)
  // Sonner defaults to its light theme; follow the app's resolved theme.
  const { resolvedTheme } = useTheme()
  return (
    <Toaster
      theme={resolvedTheme === 'dark' ? 'dark' : 'light'}
      style={TOAST_TOKENS}
      richColors
      position={phone ? 'top-center' : 'bottom-right'}
      mobileOffset={{ top: 'max(12px, env(safe-area-inset-top))' }}
      expand={true}
      visibleToasts={3}
      closeButton
      toastOptions={{
        style: {
          // Ensure action buttons are always visible
          minHeight: '48px',
        },
      }}
    />
  )
}
