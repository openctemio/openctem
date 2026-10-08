'use client'

import { useEffect, useState } from 'react'
import { discoverSignInAction } from '../actions/local-auth-actions'

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

/**
 * Email-first sign-in: once the typed email looks complete, asks the API
 * whether its domain signs in through an organization's SSO, and returns that
 * organization's slug (or null). Debounced; only the latest answer counts.
 */
export function useEmailDiscovery(email: string, enabled: boolean, delayMs = 400): string | null {
  const [org, setOrg] = useState<string | null>(null)

  useEffect(() => {
    const value = email.trim()
    if (!enabled || !EMAIL.test(value)) {
      setOrg(null)
      return
    }
    let cancelled = false
    const timer = setTimeout(() => {
      void discoverSignInAction(value).then((res) => {
        if (!cancelled) setOrg(res.next === 'sso' && res.org ? res.org : null)
      })
    }, delayMs)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [email, enabled, delayMs])

  return org
}
