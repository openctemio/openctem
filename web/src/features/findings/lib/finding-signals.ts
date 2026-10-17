/**
 * The risk signals behind a finding's priority, as short facts the "Why it
 * matters" panel shows next to the P-class: exploitation (KEV, exploit, EPSS),
 * exposure (internet, reachability) and business impact (asset criticality).
 *
 * Every signal comes from the finding response itself — no extra request —
 * and states a fact the data has. A missing fact is left out, never guessed:
 * "Not in KEV" appears only for a CVE the catalogue was checked against.
 * Unknown reachability is stated as unknown, never as unreachable.
 */

import { formatEpssPercentile, formatEpssScore } from '@/lib/epss'
import { defaultT, type TFn } from '@/features/assets/lib/default-t'
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

const MATURITY_LABEL: Record<string, { key: string; fallback: string }> = {
  weaponized: { key: 'findings.signals.weaponized', fallback: 'Weaponized exploit' },
  functional: { key: 'findings.signals.functional', fallback: 'Working exploit' },
  poc: { key: 'findings.signals.poc', fallback: 'Proof-of-concept exploit' },
  proof_of_concept: { key: 'findings.signals.poc', fallback: 'Proof-of-concept exploit' },
}

const CRITICALITY_SIGNAL: Record<string, { key: string; fallback: string }> = {
  critical: { key: 'findings.signals.criticalAsset', fallback: 'Critical asset' },
  high: { key: 'findings.signals.highAsset', fallback: 'High-criticality asset' },
  medium: { key: 'findings.signals.mediumAsset', fallback: 'Medium-criticality asset' },
  low: { key: 'findings.signals.lowAsset', fallback: 'Low-criticality asset' },
}

const EXPOSURE_SIGNAL: Record<string, { key: string; fallback: string }> = {
  public: { key: 'findings.signals.publicAsset', fallback: 'Public asset' },
  restricted: { key: 'findings.signals.restrictedAsset', fallback: 'Restricted asset' },
  private: { key: 'findings.signals.privateAsset', fallback: 'Private asset' },
  isolated: { key: 'findings.signals.isolatedAsset', fallback: 'Isolated asset' },
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

export function riskSignals(f: SignalInput, t: TFn = defaultT): RiskSignal[] {
  const out: RiskSignal[] = []
  const adv = f.advisory

  // --- Exploitation -------------------------------------------------------
  if (f.isInKev) {
    out.push({
      key: 'kev',
      group: 'exploitation',
      label: t('findings.signals.kev', 'Known exploited (CISA KEV)'),
      effect: 'raises',
      detail: f.kevDueDate
        ? t('findings.signals.kevDue', 'CISA remediation due {date}', {
            date: f.kevDueDate.slice(0, 10),
          })
        : undefined,
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
      label: t(MATURITY_LABEL[maturity].key, MATURITY_LABEL[maturity].fallback),
      effect: 'raises',
    })
  } else if (adv?.exploitAvailable || scannerExploit) {
    out.push({
      key: 'exploit',
      group: 'exploitation',
      label: t('findings.signals.publicExploit', 'Public exploit'),
      effect: 'raises',
    })
  } else if (adv && !f.isInKev) {
    // The advisory was checked and records no exploit.
    out.push({
      key: 'exploit',
      group: 'exploitation',
      label: t('findings.signals.noExploit', 'No known exploit'),
      effect: 'lowers',
    })
  }

  if (typeof f.epssScore === 'number') {
    const score = formatEpssScore(f.epssScore, f.epssScore < 0.1 ? 2 : 1)
    out.push({
      key: 'epss',
      group: 'exploitation',
      label:
        typeof f.epssPercentile === 'number'
          ? t('findings.signals.epssWithPercentile', 'EPSS {score} · {percentile} percentile', {
              score,
              percentile: formatEpssPercentile(f.epssPercentile, 0),
            })
          : t('findings.signals.epss', 'EPSS {score}', { score }),
      effect: f.epssScore >= EPSS_HIGH ? 'raises' : 'neutral',
      detail: t(
        'findings.signals.epssDetail',
        'Probability of exploitation in the next 30 days (FIRST EPSS)'
      ),
    })
  }

  // --- Exposure -----------------------------------------------------------
  const asset = f.assets[0]
  if (f.isInternetAccessible || asset?.isInternetAccessible) {
    out.push({
      key: 'internet',
      group: 'exposure',
      label: t('findings.signals.internetFacing', 'Internet-facing'),
      effect: 'raises',
    })
  } else if (f.isNetworkAccessible) {
    out.push({
      key: 'network',
      group: 'exposure',
      label: t('findings.signals.networkReachable', 'Network-reachable'),
      effect: 'neutral',
    })
  }

  const reach = f.reachableFromCount ?? 0
  if (reach > 0) {
    out.push({
      key: 'reachable',
      group: 'exposure',
      label:
        reach === 1
          ? t('findings.signals.reachableFromOne', 'Reachable from 1 entry point')
          : t('findings.signals.reachableFromMany', 'Reachable from {count} entry points', {
              count: reach,
            }),
      effect: 'raises',
    })
  } else if (f.isReachable) {
    out.push({
      key: 'reachable',
      group: 'exposure',
      label: t('findings.signals.reachable', 'Reachable'),
      effect: 'raises',
    })
  }
  // Nothing says whether an attacker can reach it: say so, never guess.
  const exposureKnown = !!asset?.exposure && asset.exposure !== 'unknown'
  if (
    asset &&
    !exposureKnown &&
    !out.some((x) => x.group === 'exposure') &&
    !asset.isInternetAccessible
  ) {
    out.push({
      key: 'reachability-unknown',
      group: 'exposure',
      label: t('findings.signals.reachabilityUnknown', 'Reachability unknown'),
      effect: 'neutral',
      detail: t(
        'findings.signals.reachabilityUnknownDetail',
        'No exposure, attack-path or call-path data for this asset yet'
      ),
    })
  }

  // --- Business impact ----------------------------------------------------
  // Not rated (none) is not a signal.
  if (asset?.criticality && CRITICALITY_SIGNAL[asset.criticality]) {
    const c = asset.criticality
    out.push({
      key: 'criticality',
      group: 'impact',
      label: t(CRITICALITY_SIGNAL[c].key, CRITICALITY_SIGNAL[c].fallback),
      effect: c === 'critical' || c === 'high' ? 'raises' : 'neutral',
    })
  }
  // "Public" says the same as "Internet-facing"; show it only when that is absent.
  const internet = out.some((x) => x.key === 'internet')
  const exposureLabel = asset?.exposure ? EXPOSURE_SIGNAL[asset.exposure] : undefined
  if (asset?.exposure && exposureLabel && !(internet && asset.exposure === 'public')) {
    out.push({
      key: 'asset-exposure',
      group: 'impact',
      label: t(exposureLabel.key, exposureLabel.fallback),
      effect: asset.exposure === 'public' ? 'raises' : 'neutral',
    })
  }

  return out
}
