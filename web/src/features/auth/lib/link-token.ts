'use client'

import { useEffect, useState } from 'react'

/**
 * The one-time token of an emailed link (/reset-password#token=…,
 * /set-password#token=…). It is read from the fragment, which the browser
 * never sends to a server, so it stays out of access logs and Referer
 * headers. A link sent before the switch carried it in the query string; that
 * still works. Either way the token is removed from the address bar and the
 * history at once.
 *
 * Returns null until the URL has been read (the first render, also on the
 * server), then the token or '' when the link has none.
 */
export function readLinkToken(): string {
  const fromHash = new URLSearchParams(window.location.hash.slice(1)).get('token')
  const fromQuery = new URLSearchParams(window.location.search).get('token')
  if (fromHash !== null || fromQuery !== null) {
    window.history.replaceState(window.history.state, '', window.location.pathname)
  }
  return fromHash ?? fromQuery ?? ''
}

export function useLinkToken(): string | null {
  const [token, setToken] = useState<string | null>(null)
  useEffect(() => {
    setToken(readLinkToken())
  }, [])
  return token
}
