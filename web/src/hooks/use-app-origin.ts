import { useSyncExternalStore } from 'react'
import { env } from '@/lib/env'

/**
 * The origin this console is served from ("https://ctem.example.com").
 *
 * Links the console builds (copy-link buttons, SCIM and MCP endpoints, invite
 * links) use `window.location.origin`; anything that shows the console's own
 * address uses this hook so it states the same host, never a hard-coded one.
 * The server and hydration render use NEXT_PUBLIC_APP_URL.
 */
export function useAppOrigin(): string {
  return useSyncExternalStore(subscribe, browserOrigin, configuredOrigin)
}

/** The host part of `useAppOrigin()` ("ctem.example.com"). */
export function useAppHost(): string {
  return hostOf(useAppOrigin())
}

const subscribe = () => () => {}
const browserOrigin = () => window.location.origin || configuredOrigin()

function configuredOrigin(): string {
  try {
    return new URL(env.app.url).origin
  } catch {
    return ''
  }
}

function hostOf(origin: string): string {
  try {
    return new URL(origin).host
  } catch {
    return ''
  }
}
