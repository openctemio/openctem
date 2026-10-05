/**
 * The risk signals behind a finding's priority, as short facts the "Why it
 * matters" panel shows next to the P-class: exploitation (KEV, exploit, EPSS),
 * exposure (internet, reachability) and business impact (asset criticality).
 *
 * Every signal comes from the finding response itself — no extra request —
 * and states a fact the data has. A missing fact is left out, never guessed:
 * "Not in KEV" appears only for a CVE the catalogue was checked against.
 */

import { formatEpssPercentile, formatEpssScore } from '@/lib/epss'
import type { FindingDetail } from '../types'

/** `raises` makes the finding more urgent; `lowers` less; `neutral` is context. */
export type SignalEffect = 'raises' | 'lowers' | 'neutral'

export type SignalGroup = 'exploitation' | 'exposure' | 'impact'

export interface RiskSignal {
  key: string
  group: SignalGroup
  label: string
  effect: SignalEffect
  /** One line saying where the fact comes from, for the tooltip / screen readers. */
  detail?: string
}

/** EPSS at or above this probability counts as likely to be exploited. */
export const EPSS_HIGH = 0.1

const MATURITY_LABEL: Record<string, string> = {
  weaponized: 'Weaponized exploit',
  functional: 'Working exploit',
  poc: 'Proof-of-concept exploit',
  proof_of_concept: 'Proof-of-concept exploit',
}

type SignalInput = Pick<
  FindingDetail,
  | 'cve'
  | 'isInKev'
  | 'kevDueDate'
  | 'epssScore'
  | 'epssPercentile'
  | 'advisory'
  | 'isInternetAccessible'
  | 'isReachable'
  | 'reachableFromCount'
  | 'isNetworkAccessible'
  | 'assets'
  | 'metadata'
  | 'scannerFacts'
>

export function riskSignals(f: SignalInput): RiskSignal[] {
  const out: RiskSignal[] = []
  const adv = f.advisory

  // --- Exploitation -------------------------------------------------------
  if (f.isInKev) {
    out.push({
      key: 'kev',
      group: 'exploitation',
      label: 'Known exploited (CISA KEV)',
      effect: 'raises',
      detail: f.kevDueDate ? `CISA remediation due ${f.kevDueDate.slice(0, 10)}` : undefined,
    })
  }

  const maturity = adv?.exploitMaturity?.toLowerCase()
  // The finding's own exploit verdict (findings.exploit_available, the
  // column every list filter and group reads); the metadata key is the
  // pre-column copy, kept for findings read from older API builds.
  const scannerExploit =
    f.scannerFacts?.exploitAvailable === true || f.metadata?.scanner_exploit_available === true
  if (maturity && MATURITY_LABEL[maturity]) {
    out.push({
      key: 'exploit',
      group: 'exploitation',
      label: MATURITY_LABEL[maturity],
      effect: 'raises',
    })
  } else if (adv?.exploitAvailable || scannerExploit) {
    out.push({ key: 'exploit', group: 'exploitation', label: 'Public exploit', effect: 'raises' })
  } else if (adv && !f.isInKev) {
    // The advisory was checked and records no exploit.
    out.push({
      key: 'exploit',
      group: 'exploitation',
      label: 'No known exploit',
      effect: 'lowers',
    })
  }

  if (typeof f.epssScore === 'number') {
    const pct =
      typeof f.epssPercentile === 'number'
        ? ` · ${formatEpssPercentile(f.epssPercentile, 0)} percentile`
        : ''
    out.push({
      key: 'epss',
      group: 'exploitation',
      label: `EPSS ${formatEpssScore(f.epssScore, f.epssScore < 0.1 ? 2 : 1)}${pct}`,
      effect: f.epssScore >= EPSS_HIGH ? 'raises' : 'neutral',
      detail: 'Probability of exploitation in the next 30 days (FIRST EPSS)',
    })
  }

  // --- Exposure -----------------------------------------------------------
  const asset = f.assets[0]
  if (f.isInternetAccessible || asset?.isInternetAccessible) {
    out.push({ key: 'internet', group: 'exposure', label: 'Internet-facing', effect: 'raises' })
  } else if (f.isNetworkAccessible) {
    out.push({ key: 'network', group: 'exposure', label: 'Network-reachable', effect: 'neutral' })
  }

  const reach = f.reachableFromCount ?? 0
  if (reach > 0) {
    out.push({
      key: 'reachable',
      group: 'exposure',
      label: `Reachable from ${reach} entry point${reach === 1 ? '' : 's'}`,
      effect: 'raises',
    })
  } else if (f.isReachable) {
    out.push({ key: 'reachable', group: 'exposure', label: 'Reachable', effect: 'raises' })
  }

  // --- Business impact ----------------------------------------------------
  if (asset?.criticality && asset.criticality !== 'info') {
    const c = asset.criticality
    out.push({
      key: 'criticality',
      group: 'impact',
      label:
        c === 'critical'
          ? 'Critical asset'
          : `${c.charAt(0).toUpperCase()}${c.slice(1)}-criticality asset`,
      effect: c === 'critical' || c === 'high' ? 'raises' : 'neutral',
    })
  }
  // "Public" says the same as "Internet-facing"; show it only when that is absent.
  const internet = out.some((x) => x.key === 'internet')
  if (
    asset?.exposure &&
    asset.exposure !== 'unknown' &&
    !(internet && asset.exposure === 'public')
  ) {
    out.push({
      key: 'asset-exposure',
      group: 'impact',
      label: `${asset.exposure.charAt(0).toUpperCase()}${asset.exposure.slice(1)} asset`,
      effect: asset.exposure === 'public' ? 'raises' : 'neutral',
    })
  }

  return out
}
