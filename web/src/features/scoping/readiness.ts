/**
 * Scoping readiness: is the program's scope written down for this cycle? One
 * row per ctem.org scoping artifact, each with the page that fixes it. These
 * are readiness checks, not a score (ctem.org warns against vanity metrics);
 * outcome metrics live in Program Health.
 *
 * Pure, so the rules are unit-tested; the page and the dashboard tile share it.
 */
import type { ScopingSummary } from './api'
import type { useTranslation } from '@/context/i18n-provider'

type Translate = ReturnType<typeof useTranslation>['t']

export interface ReadinessRow {
  key: string
  label: string
  ready: boolean
  /** What was measured, e.g. "3 of 9" (already translated). */
  value: string
  /** The page that fixes it, and the verb on its button. */
  href: string
  action: string
  /** Module the row is about; hidden when that module is off. */
  module?: string
}

const SEP = ' · '

export function readinessRows(s: ScopingSummary, t: Translate): ReadinessRow[] {
  const cycle = s.active_cycle
  const active = cycle?.status === 'active'
  const charterWritten = !!cycle && cycle.objectives + cycle.success_criteria > 0
  const cj = s.crown_jewels
  const svc = s.business_services
  const assets = s.assets
  const tm = s.threat_models
  const of = (n: number, total: number) =>
    t('scoping.readiness.ofTotal', '{n} of {total}', { n, total })
  const noCycle = t('scoping.readiness.noCycle', 'No cycle')

  return [
    {
      key: 'cycle',
      label: t('scoping.readiness.cycle.label', 'Cycle active with a charter'),
      ready: active && charterWritten,
      value: cycle
        ? [
            cycle.name,
            t(`scoping.cycleStatus.${cycle.status}`, cycle.status),
            ...(charterWritten ? [] : [t('scoping.readiness.cycle.noCharter', 'no charter')]),
          ].join(SEP)
        : noCycle,
      href: cycle ? `/cycles/${cycle.id}` : '/cycles',
      action: cycle
        ? t('scoping.readiness.action.open', 'Open')
        : t('scoping.readiness.action.start', 'Start'),
      module: 'ctem_cycles',
    },
    {
      key: 'crown_jewels',
      label: t('scoping.readiness.crownJewels.label', 'Crown jewels identified'),
      ready: cj.total > 0,
      value: t('scoping.readiness.assetCount', '{n, plural, one {# asset} other {# assets}}', {
        n: cj.total,
      }),
      href: '/crown-jewels',
      action:
        cj.total > 0
          ? t('scoping.readiness.action.review', 'Review')
          : t('scoping.readiness.action.designate', 'Designate'),
      module: 'crown_jewels',
    },
    {
      key: 'crown_jewel_owners',
      label: t('scoping.readiness.owners.label', 'Crown jewels have an owner'),
      ready: cj.total > 0 && cj.with_owner >= cj.total,
      value: of(cj.with_owner, cj.total),
      href: '/assets?is_crown_jewel=true&has_owner=false',
      action: t('scoping.readiness.action.assign', 'Assign'),
      module: 'crown_jewels',
    },
    {
      key: 'services',
      label: t('scoping.readiness.services.label', 'Business services defined'),
      ready: svc.total > 0,
      value: t(
        'scoping.readiness.serviceCount',
        '{n, plural, one {# service} other {# services}}',
        { n: svc.total }
      ),
      href: '/business-services',
      action:
        svc.total > 0
          ? t('scoping.readiness.action.open', 'Open')
          : t('scoping.readiness.action.define', 'Define'),
      module: 'business_services',
    },
    {
      key: 'service_assets',
      label: t('scoping.readiness.serviceAssets.label', 'Services linked to their assets'),
      ready: svc.total > 0 && svc.with_assets >= svc.total,
      value: of(svc.with_assets, svc.total),
      href: '/business-services',
      action: t('scoping.readiness.action.link', 'Link'),
      module: 'business_services',
    },
    {
      key: 'business_units',
      label: t('scoping.readiness.businessUnits.label', 'Assets mapped to a business unit'),
      ready: assets.total > 0 && assets.in_business_unit >= assets.total,
      value: of(assets.in_business_unit, assets.total),
      href: s.business_units.total > 0 ? '/assets' : '/business-units',
      action:
        s.business_units.total > 0
          ? t('scoping.readiness.action.map', 'Map')
          : t('scoping.readiness.action.createUnits', 'Create units'),
      module: 'business_units',
    },
    {
      key: 'boundary',
      label: t(
        'scoping.readiness.boundary.label',
        'Boundary in effect (scope entries and exclusions)'
      ),
      ready: s.boundary.targets > 0,
      value: [
        t(
          'scoping.readiness.boundary.entries',
          '{n, plural, one {# entry} other {# entries}} in effect',
          { n: s.boundary.targets }
        ),
        t(
          'scoping.readiness.boundary.exclusions',
          '{n, plural, one {# exclusion} other {# exclusions}}',
          { n: s.boundary.exclusions }
        ),
        ...(s.boundary.targets_waiting > 0
          ? [
              t('scoping.readiness.boundary.waiting', '{n} waiting for approval', {
                n: s.boundary.targets_waiting,
              }),
            ]
          : []),
      ].join(SEP),
      href: '/scope',
      action: t('scoping.readiness.action.open', 'Open'),
      module: 'scope_config',
    },
    {
      key: 'attacker_profiles',
      label: t('scoping.readiness.profiles.label', 'Attacker profiles chosen for the cycle'),
      ready: !!cycle && cycle.attacker_profiles > 0,
      value: cycle
        ? t('scoping.readiness.profileCount', '{n, plural, one {# profile} other {# profiles}}', {
            n: cycle.attacker_profiles,
          })
        : noCycle,
      href: cycle ? `/cycles/${cycle.id}?tab=profiles` : '/cycles',
      action: t('scoping.readiness.action.choose', 'Choose'),
      module: 'ctem_cycles',
    },
    {
      key: 'threat_models',
      label: t('scoping.readiness.threatModels.label', 'Threat model for each crown jewel'),
      ready: cj.total > 0 && tm.crown_jewels_covered >= cj.total,
      value: of(tm.crown_jewels_covered, cj.total),
      href: '/threat-model',
      action: t('scoping.readiness.action.generate', 'Generate'),
      module: 'threat_model',
    },
  ]
}

/** Rows the tenant can act on: a row about a module that is off is left out. */
export function visibleReadiness(
  rows: ReadinessRow[],
  moduleOn: (module: string) => boolean
): ReadinessRow[] {
  return rows.filter((r) => !r.module || moduleOn(r.module))
}

export function readinessScore(rows: ReadinessRow[]): { ready: number; total: number } {
  return { ready: rows.filter((r) => r.ready).length, total: rows.length }
}
