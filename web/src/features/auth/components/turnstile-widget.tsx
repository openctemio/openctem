'use client'

/**
 * Cloudflare Turnstile check for the public sign-up forms (registration,
 * request access). Rendered only when the API reports a site key
 * (/auth/providers captcha_site_key); the API then requires the token
 * (CAPTCHA_TURNSTILE_SECRET). The script is added by this bundle, which the
 * CSP trusts through its nonce ('strict-dynamic'); its iframe is allowed by
 * frame-src https://challenges.cloudflare.com.
 */

import { useEffect, useRef } from 'react'

import { useTranslation } from '@/context/i18n-provider'

const SCRIPT_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'

interface TurnstileApi {
  render: (el: HTMLElement, opts: Record<string, unknown>) => string
  reset: (id?: string) => void
  remove: (id: string) => void
}

declare global {
  interface Window {
    turnstile?: TurnstileApi
  }
}

let scriptPromise: Promise<void> | null = null

function loadScript(): Promise<void> {
  if (typeof window === 'undefined') return Promise.resolve()
  if (window.turnstile) return Promise.resolve()
  if (!scriptPromise) {
    scriptPromise = new Promise((resolve, reject) => {
      const s = document.createElement('script')
      s.src = SCRIPT_SRC
      s.async = true
      s.onload = () => resolve()
      s.onerror = () => {
        scriptPromise = null
        reject(new Error('turnstile script failed to load'))
      }
      document.head.appendChild(s)
    })
  }
  return scriptPromise
}

export interface TurnstileWidgetProps {
  siteKey: string
  /** The token once the check passes; '' when it expires or fails. */
  onToken: (token: string) => void
  /** Bump to get a fresh token (a token works once). */
  resetSignal?: number
}

export function TurnstileWidget({ siteKey, onToken, resetSignal = 0 }: TurnstileWidgetProps) {
  const { t, locale } = useTranslation()
  const box = useRef<HTMLDivElement>(null)
  const widgetId = useRef<string | null>(null)
  const onTokenRef = useRef(onToken)
  useEffect(() => {
    onTokenRef.current = onToken
  }, [onToken])

  useEffect(() => {
    let cancelled = false
    loadScript()
      .then(() => {
        if (cancelled || !box.current || !window.turnstile) return
        widgetId.current = window.turnstile.render(box.current, {
          sitekey: siteKey,
          language: locale,
          callback: (token: string) => onTokenRef.current(token),
          'expired-callback': () => onTokenRef.current(''),
          'error-callback': () => onTokenRef.current(''),
        })
      })
      .catch(() => onTokenRef.current(''))
    return () => {
      cancelled = true
      if (widgetId.current && window.turnstile) window.turnstile.remove(widgetId.current)
      widgetId.current = null
    }
  }, [siteKey, locale])

  useEffect(() => {
    if (resetSignal && widgetId.current && window.turnstile) {
      window.turnstile.reset(widgetId.current)
      onTokenRef.current('')
    }
  }, [resetSignal])

  return (
    <div
      ref={box}
      className="min-h-[65px]"
      role="group"
      aria-label={t('auth.captcha.label', 'Security check')}
    />
  )
}
