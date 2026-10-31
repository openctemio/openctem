/**
 * Client guard for version skew after a deploy.
 *
 * A tab that stays open across a deploy keeps the old client bundle. Its server
 * action ids no longer exist on the new server, so the server answers 404 with
 * `x-nextjs-action-not-found: 1` and the action call fails ("Failed to find
 * Server Action ... older or newer deployment"). Login, SSO start, link
 * confirmation and every other server action hit this.
 *
 * Next.js version-skew protection (`deploymentId` in next.config.ts) makes
 * navigations hard-reload on a mismatch; this guard covers the call that is
 * already in flight: it watches every fetch response for the not-found marker,
 * shows one notice and reloads the page once. A reload that did not cure the
 * problem is not repeated within RELOAD_WINDOW_MS, so there is no reload loop.
 */

import { toast } from 'sonner'

import { translate } from '@/lib/i18n'

export const ACTION_NOT_FOUND_HEADER = 'x-nextjs-action-not-found'
export const RELOAD_STORAGE_KEY = 'oc-skew-reload-at'
export const RELOAD_WINDOW_MS = 60_000
const RELOAD_DELAY_MS = 1200
const TOAST_ID = 'deployment-updated'

export interface SkewDeps {
  now?: () => number
  reload?: () => void
  notify?: () => void
  storage?: Pick<Storage, 'getItem' | 'setItem'> | null
  delay?: (fn: () => void, ms: number) => void
}

function defaultStorage(): SkewDeps['storage'] {
  try {
    return window.sessionStorage
  } catch {
    return null
  }
}

function defaultNotify(): void {
  const text = translate(
    {},
    'errors.APP_UPDATED_RELOADING',
    '{product} was updated. Reloading to the latest version.'
  )
  toast.info(text, { id: TOAST_ID, duration: RELOAD_DELAY_MS * 3 })
}

/**
 * handleActionNotFound shows the notice and reloads, at most once per
 * RELOAD_WINDOW_MS. Returns true when it scheduled a reload.
 */
export function handleActionNotFound(deps: SkewDeps = {}): boolean {
  const now = deps.now ?? Date.now
  const storage = deps.storage === undefined ? defaultStorage() : deps.storage
  const reload = deps.reload ?? (() => window.location.reload())
  const notify = deps.notify ?? defaultNotify
  const delay = deps.delay ?? ((fn, ms) => void setTimeout(fn, ms))

  let last = 0
  try {
    last = Number(storage?.getItem(RELOAD_STORAGE_KEY) ?? 0) || 0
  } catch {
    // storage blocked
  }
  const t = now()
  if (last > 0 && t - last < RELOAD_WINDOW_MS) return false
  try {
    storage?.setItem(RELOAD_STORAGE_KEY, String(t))
  } catch {
    // ignore
  }
  notify()
  delay(reload, RELOAD_DELAY_MS)
  return true
}

/** isActionNotFound is true for the response Next sends for an unknown action id. */
export function isActionNotFound(res: Response | null | undefined): boolean {
  return !!res && res.status === 404 && res.headers.get(ACTION_NOT_FOUND_HEADER) === '1'
}

let installed = false

/**
 * installDeploymentSkewGuard wraps window.fetch once. Every server action goes
 * through fetch, so one wrapper covers all of them, whatever the caller does
 * with the error. Returns the function that restores the original fetch.
 */
export function installDeploymentSkewGuard(deps: SkewDeps = {}): () => void {
  if (typeof window === 'undefined' || installed) return () => {}
  const original = window.fetch
  installed = true
  window.fetch = async function guardedFetch(...args: Parameters<typeof fetch>) {
    const res = await original.apply(window, args)
    if (isActionNotFound(res)) handleActionNotFound(deps)
    return res
  }
  return () => {
    window.fetch = original
    installed = false
  }
}
