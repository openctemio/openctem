'use client'

import { useEffect, useRef } from 'react'

/**
 * Cloudflare Turnstile, rendered explicitly. Shown only when the API reports a
 * site key (`captcha_site_key` on GET /auth/providers); the API verifies the
 * token (CAPTCHA_TURNSTILE_SECRET). The page's CSP allows the Turnstile
 * origin only on the CAPTCHA routes (src/lib/middleware/csp.ts); the script is
 * added here by our own code, which the policy's 'strict-dynamic' trusts.
 */

const SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'

interface TurnstileApi {
  render: (
    el: HTMLElement,
    opts: {
      sitekey: string
      callback: (token: string) => void
      'expired-callback': () => void
      'error-callback': () => void
      theme?: 'auto' | 'light' | 'dark'
    }
  ) => string
  remove: (id: string) => void
}

declare global {
  interface Window {
    turnstile?: TurnstileApi
  }
}

let loading: Promise<TurnstileApi> | null = null

/** Loads the Turnstile script once per page. */
export function loadTurnstile(doc: Document = document): Promise<TurnstileApi> {
  if (typeof window !== 'undefined' && window.turnstile) return Promise.resolve(window.turnstile)
  if (loading) return loading
  loading = new Promise<TurnstileApi>((resolve, reject) => {
    const script = doc.createElement('script')
    script.src = SCRIPT_URL
    script.async = true
    script.defer = true
    script.onload = () =>
      window.turnstile ? resolve(window.turnstile) : reject(new Error('turnstile unavailable'))
    script.onerror = () => {
      loading = null
      reject(new Error('turnstile failed to load'))
    }
    doc.head.appendChild(script)
  })
  return loading
}

export interface TurnstileWidgetProps {
  siteKey: string
  /** A fresh token, or '' when it expired or failed (submit stays disabled). */
  onToken: (token: string) => void
  /** Called when the widget cannot load (blocked network, CSP). */
  onError?: () => void
}

export function TurnstileWidget({ siteKey, onToken, onError }: TurnstileWidgetProps) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let id: string | null = null
    let cancelled = false
    loadTurnstile()
      .then((api) => {
        if (cancelled || !ref.current) return
        id = api.render(ref.current, {
          sitekey: siteKey,
          theme: 'auto',
          callback: (token) => onToken(token),
          'expired-callback': () => onToken(''),
          'error-callback': () => {
            onToken('')
            onError?.()
          },
        })
      })
      .catch(() => {
        if (!cancelled) onError?.()
      })
    return () => {
      cancelled = true
      if (id && window.turnstile) window.turnstile.remove(id)
    }
  }, [siteKey, onToken, onError])

  return <div ref={ref} data-testid="turnstile" className="flex justify-center" />
}
