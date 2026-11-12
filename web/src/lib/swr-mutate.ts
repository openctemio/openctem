/**
 * `mutate` for code outside a component (module helpers, event handlers that
 * cannot call `useSWRConfig`).
 *
 * The dashboard keeps its SWR cache per organization epoch: every switch of
 * organization mounts a fresh cache (src/components/layout/tenant-epoch-boundary.tsx),
 * so no answer, dedupe entry or in-flight read of the previous organization
 * can reach the new one. SWR's global `mutate` from 'swr' only reaches the
 * default cache, so it is banned by ESLint (no-restricted-imports); this one
 * forwards to the cache of the current epoch (the default cache outside the
 * dashboard, e.g. the sign-in pages and the platform console).
 * Rule: web/docs/organization-switch.md.
 */

// The one place that binds the default cache (exempt in eslint.config.mjs).
import { mutate as defaultMutate, type ScopedMutator } from 'swr'

// Read SWR's default mutate on use, not at import (test files mock 'swr').
let bound: ScopedMutator | null = null

/** Binds the epoch cache's mutate; returns the unbind. */
export function bindEpochMutate(m: ScopedMutator): () => void {
  bound = m
  return () => {
    if (bound === m) bound = null
  }
}

type AnyMutate = (...a: Parameters<ScopedMutator>) => ReturnType<ScopedMutator>

/** Mutates a key of the current epoch's cache (same signature as SWR's). */
export const mutate: ScopedMutator = ((...args: Parameters<ScopedMutator>) =>
  ((bound ?? defaultMutate) as AnyMutate)(...args)) as ScopedMutator

/** The default cache's mutate, for data that is not organization data (the membership list). */
export const accountMutate: ScopedMutator = ((...args: Parameters<ScopedMutator>) =>
  (defaultMutate as AnyMutate)(...args)) as ScopedMutator
