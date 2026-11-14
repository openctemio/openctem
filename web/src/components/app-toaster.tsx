'use client'

import * as React from 'react'
import { useTheme } from 'next-themes'
import { Toaster, toast } from 'sonner'
import { statusToneVars } from '@/lib/status-colors'
import { takeSessionFlash } from '@/lib/session-navigation'

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

const resolved = statusToneVars('resolved')
const progress = statusToneVars('progress')
const accepted = statusToneVars('accepted')

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
  '--success-bg': resolved.bg,
  '--success-text': resolved.fg,
  '--success-border': resolved.border,
  '--info-bg': progress.bg,
  '--info-text': progress.fg,
  '--info-border': progress.border,
  '--warning-bg': accepted.bg,
  '--warning-text': accepted.fg,
  '--warning-border': accepted.border,
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
    <>
      <ToasterFrame phone={phone} dark={resolvedTheme === 'dark'} />
      <SessionFlashToast />
    </>
  )
}

/**
 * Shows, once, the message a page kept before it reloaded into a new session
 * (src/lib/session-navigation.ts). Rendered after the Toaster, so the
 * Toaster is listening when the toast is raised.
 */
function SessionFlashToast() {
  React.useEffect(() => {
    const flash = takeSessionFlash()
    if (!flash) return
    const show = flash.kind === 'success' ? toast.success : toast.info
    show(flash.title, flash.description ? { description: flash.description } : undefined)
  }, [])
  return null
}

function ToasterFrame({ phone, dark }: { phone: boolean; dark: boolean }) {
  return (
    <Toaster
      theme={dark ? 'dark' : 'light'}
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
