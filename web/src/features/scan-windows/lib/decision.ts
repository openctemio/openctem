/**
 * What a window decision means in words: for one target (open, waits until,
 * never opens), for a queued task's hold, and for the targets of a run that
 * wait. Shared by the asset page, the New Scan preview, the trigger toast and
 * the run views so they all say the same thing.
 */
import { ApiClientError } from '@/lib/api/error-handler'

import type {
  RunWindowWaits,
  TargetWait,
  WindowBlock,
  WindowDecision,
  WindowHold,
  WindowRef,
} from '../types'
import { englishT, formatInZone, type Translate } from './schedule'

/** A trigger refused because a target's windows never open (409). */
export const SCAN_WINDOW_NEVER_OPENS = 'SCAN_WINDOW_NEVER_OPENS'
/** An override asked for without an authenticator app (403). */
export const WINDOW_OVERRIDE_NEEDS_TOTP = 'WINDOW_OVERRIDE_NEEDS_TOTP'
/** An override asked for with a wrong authenticator code (403). */
export const WINDOW_OVERRIDE_INVALID_CODE = 'WINDOW_OVERRIDE_INVALID_CODE'
/** A selector naming an object that is not the organization's (422). */
export const SCAN_WINDOW_UNKNOWN_REFERENCE = 'SCAN_WINDOW_UNKNOWN_REFERENCE'

/** The API error code of err (top level or in details), or null. */
export function apiErrorCode(err: unknown): string | null {
  if (!(err instanceof ApiClientError)) return null
  const fromDetails = (err.details as { code?: unknown } | undefined)?.code
  return typeof fromDetails === 'string' && fromDetails ? fromDetails : err.code || null
}

/** Was the trigger refused because a target's windows never open? */
export function isNeverOpensRefusal(err: unknown): boolean {
  return (
    apiErrorCode(err) === SCAN_WINDOW_NEVER_OPENS ||
    (err instanceof ApiClientError && err.code === SCAN_WINDOW_NEVER_OPENS)
  )
}

/** "Patch night (policy)" / "Acme (bug-bounty program)". */
export function windowRefLabel(r: WindowRef | WindowBlock, t: Translate = englishT): string {
  const name = r.name || t('scanWindows.ref.unnamed', 'Unnamed window')
  return r.origin === 'program'
    ? t('scanWindows.ref.program', '{name} (bug-bounty program)', { name })
    : t('scanWindows.ref.policy', '{name} (policy)', { name })
}

/** The blocking windows' names, joined. */
export function blockingNames(blocks: WindowBlock[] | undefined, t: Translate = englishT): string {
  return (blocks ?? []).map((b) => windowRefLabel(b, t)).join(', ')
}

export type DecisionState = 'ungoverned' | 'open' | 'waits' | 'never'

export function decisionState(
  d: Pick<WindowDecision, 'governed' | 'open' | 'never'>
): DecisionState {
  if (!d.governed) return 'ungoverned'
  if (d.open) return 'open'
  if (d.never) return 'never'
  return 'waits'
}

/** A short label for a decision: "Open now", "Waits until …", "Never opens". */
export function decisionLabel(
  d: Pick<WindowDecision, 'governed' | 'open' | 'never' | 'next_open_at' | 'closes_at'>,
  t: Translate = englishT
): string {
  switch (decisionState(d)) {
    case 'ungoverned':
      return t('scanWindows.decision.ungoverned', 'No scan window applies')
    case 'open':
      return d.closes_at
        ? t('scanWindows.decision.openUntil', 'Open now, until {at}', {
            at: formatInZone(d.closes_at),
          })
        : t('scanWindows.decision.open', 'Open now')
    case 'never':
      return t('scanWindows.decision.never', 'Never opens')
    default:
      return d.next_open_at
        ? t('scanWindows.decision.waits', 'Waits until {at}', { at: formatInZone(d.next_open_at) })
        : t('scanWindows.decision.waitsUnknown', 'Waits for its window')
  }
}

/**
 * The line under a queued task that waits for a window (RunTask.window_hold):
 * why, which windows, and when it may run.
 */
export function holdText(h: WindowHold, t: Translate = englishT): string {
  const names = blockingNames(h.blocking, t)
  const at = formatInZone(h.next_open_at)
  switch (h.reason) {
    case 'concurrency':
      return t(
        'scanWindows.hold.concurrency',
        'Waiting: the concurrency cap of {names} is reached; tries again shortly.',
        {
          names: names || t('scanWindows.hold.aWindow', 'a scan window'),
        }
      )
    case 'closed':
      return at
        ? t(
            'scanWindows.hold.closed',
            'The window closed while it was running; runs again at {at}.',
            { at }
          )
        : t(
            'scanWindows.hold.closedNoTime',
            'The window closed while it was running; runs again when it reopens.'
          )
    default:
      if (h.never) {
        return t(
          'scanWindows.hold.never',
          'Waiting for scan window {names}, which never opens: fix the policy.',
          {
            names,
          }
        )
      }
      return at
        ? t('scanWindows.hold.window', 'Waiting for scan window {names}, opens at {at}.', {
            names,
            at,
          })
        : t('scanWindows.hold.windowNoTime', 'Waiting for scan window {names}.', { names })
  }
}

/** The first and last opening among waiting targets (never-opening ones skipped). */
export function openingRange(waiting: TargetWait[] | undefined): { first?: string; last?: string } {
  const times = (waiting ?? [])
    .filter((w) => !w.never && w.next_open_at)
    .map((w) => w.next_open_at as string)
    .sort((a, b) => new Date(a).getTime() - new Date(b).getTime())
  return { first: times[0], last: times[times.length - 1] }
}

/** "3 targets wait for their scan window; the first opens …, the last …". */
export function waitsSummary(
  w: Pick<RunWindowWaits, 'waiting_count' | 'waiting' | 'next_open_at'>,
  t: Translate = englishT
): string {
  const n = w.waiting_count ?? w.waiting?.length ?? 0
  const { first, last } = openingRange(w.waiting)
  const head =
    n === 1
      ? t('scanWindows.waits.one', '1 target waits for its scan window')
      : t('scanWindows.waits.many', '{n} targets wait for their scan windows', { n })
  if (first && last && first !== last) {
    return `${head}; ${t('scanWindows.waits.range', 'the first opens {first}, the last {last}', {
      first: formatInZone(first),
      last: formatInZone(last),
    })}.`
  }
  const at = first ?? w.next_open_at
  if (!at) return `${head}.`
  const when =
    n === 1
      ? t('scanWindows.waits.atOne', 'it opens {at}', { at: formatInZone(at) })
      : t('scanWindows.waits.atMany', 'they open {at}', { at: formatInZone(at) })
  return `${head}; ${when}.`
}
