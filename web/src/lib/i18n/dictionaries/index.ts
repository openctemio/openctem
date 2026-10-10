// The message catalogs, one JSON file per namespace (the first segment of
// every key) and locale: en/<namespace>.json and vi/<namespace>.json. Keys
// keep their full dotted name inside the file, so `t('scans.list.title')`
// lives in en/scans.json. Separate files keep pull requests that add text
// to different features from touching the same file. A new namespace needs
// one import per locale below; dictionaries.test.ts fails on a file that is
// not imported, a key in the wrong file, a key in two files, or en and vi
// key sets that differ.

import en_activity from './en/activity.json'
import en_actor from './en/actor.json'
import en_admin from './en/admin.json'
import en_announcements from './en/announcements.json'
import en_assetSources from './en/assetSources.json'
import en_assets from './en/assets.json'
import en_assetTimeline from './en/assetTimeline.json'
import en_auth from './en/auth.json'
import en_common from './en/common.json'
import en_components from './en/components.json'
import en_criticality from './en/criticality.json'
import en_findings from './en/findings.json'
import en_help from './en/help.json'
import en_nav from './en/nav.json'
import en_org from './en/org.json'
import en_plan from './en/plan.json'
import en_programs from './en/programs.json'
import en_scanWindows from './en/scanWindows.json'
import en_scans from './en/scans.json'
import en_scope from './en/scope.json'
import en_sensors from './en/sensors.json'
import en_settings from './en/settings.json'
import en_severity from './en/severity.json'
import en_userMenu from './en/userMenu.json'
import en_workflowStages from './en/workflowStages.json'
import vi_activity from './vi/activity.json'
import vi_actor from './vi/actor.json'
import vi_admin from './vi/admin.json'
import vi_announcements from './vi/announcements.json'
import vi_assetSources from './vi/assetSources.json'
import vi_assets from './vi/assets.json'
import vi_assetTimeline from './vi/assetTimeline.json'
import vi_auth from './vi/auth.json'
import vi_common from './vi/common.json'
import vi_components from './vi/components.json'
import vi_criticality from './vi/criticality.json'
import vi_findings from './vi/findings.json'
import vi_help from './vi/help.json'
import vi_nav from './vi/nav.json'
import vi_org from './vi/org.json'
import vi_plan from './vi/plan.json'
import vi_programs from './vi/programs.json'
import vi_scanWindows from './vi/scanWindows.json'
import vi_scans from './vi/scans.json'
import vi_scope from './vi/scope.json'
import vi_sensors from './vi/sensors.json'
import vi_settings from './vi/settings.json'
import vi_severity from './vi/severity.json'
import vi_userMenu from './vi/userMenu.json'
import vi_workflowStages from './vi/workflowStages.json'

export type Dictionary = Record<string, string>

/** Namespace name -> that namespace's catalog file, per locale. */
export const enNamespaces: Record<string, Dictionary> = {
  activity: en_activity,
  actor: en_actor,
  admin: en_admin,
  announcements: en_announcements,
  assetSources: en_assetSources,
  assets: en_assets,
  assetTimeline: en_assetTimeline,
  auth: en_auth,
  common: en_common,
  components: en_components,
  criticality: en_criticality,
  findings: en_findings,
  help: en_help,
  nav: en_nav,
  org: en_org,
  plan: en_plan,
  programs: en_programs,
  scanWindows: en_scanWindows,
  scans: en_scans,
  scope: en_scope,
  sensors: en_sensors,
  settings: en_settings,
  severity: en_severity,
  userMenu: en_userMenu,
  workflowStages: en_workflowStages,
}

export const viNamespaces: Record<string, Dictionary> = {
  activity: vi_activity,
  actor: vi_actor,
  admin: vi_admin,
  announcements: vi_announcements,
  assetSources: vi_assetSources,
  assets: vi_assets,
  assetTimeline: vi_assetTimeline,
  auth: vi_auth,
  common: vi_common,
  components: vi_components,
  criticality: vi_criticality,
  findings: vi_findings,
  help: vi_help,
  nav: vi_nav,
  org: vi_org,
  plan: vi_plan,
  programs: vi_programs,
  scanWindows: vi_scanWindows,
  scans: vi_scans,
  scope: vi_scope,
  sensors: vi_sensors,
  settings: vi_settings,
  severity: vi_severity,
  userMenu: vi_userMenu,
  workflowStages: vi_workflowStages,
}

const merge = (parts: Record<string, Dictionary>): Dictionary =>
  Object.assign({}, ...Object.values(parts)) as Dictionary

export const en: Dictionary = merge(enNamespaces)
export const vi: Dictionary = merge(viNamespaces)
