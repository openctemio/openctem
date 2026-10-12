'use client'

import * as React from 'react'
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
 * The app's toaster. Bottom right on larger screens; at the top on phones,
 * where a dialog is a bottom sheet whose footer (Create, Save) is pinned at
 * the bottom of the screen: a toast there would cover the very button the
 * user needs after an error. The top inset clears the notch.
 */
export function AppToaster() {
  const phone = React.useSyncExternalStore(subscribe, isPhoneNow, isPhoneOnServer)
  return (
    <Toaster
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
