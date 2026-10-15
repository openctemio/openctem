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
import en_assetFreshness from './en/assetFreshness.json'
import en_assetCoverage from './en/assetCoverage.json'
import en_assetSources from './en/assetSources.json'
import en_assets from './en/assets.json'
import en_assetTimeline from './en/assetTimeline.json'
import en_attackSurface from './en/attackSurface.json'
import en_easmReview from './en/easmReview.json'
import en_auth from './en/auth.json'
import en_automations from './en/automations.json'
import en_common from './en/common.json'
import en_components from './en/components.json'
import en_confirm from './en/confirm.json'
import en_criticality from './en/criticality.json'
import en_findings from './en/findings.json'
import en_exceptions from './en/exceptions.json'
import en_exposures from './en/exposures.json'
import en_help from './en/help.json'
import en_insights from './en/insights.json'
import en_licensePolicy from './en/licensePolicy.json'
import en_lookalikes from './en/lookalikes.json'
import en_nav from './en/nav.json'
import en_networkSeeds from './en/networkSeeds.json'
import en_org from './en/org.json'
import en_pentest from './en/pentest.json'
import en_pentestCampaigns from './en/pentestCampaigns.json'
import en_pentestChecklists from './en/pentestChecklists.json'
import en_plan from './en/plan.json'
import en_prioritization from './en/prioritization.json'
import en_programs from './en/programs.json'
import en_remediation from './en/remediation.json'
import en_reports from './en/reports.json'
import en_scanWindows from './en/scanWindows.json'
import en_tenableSc from './en/tenableSc.json'
import en_scans from './en/scans.json'
import en_scope from './en/scope.json'
import en_sensors from './en/sensors.json'
import en_settings from './en/settings.json'
import en_riskScore from './en/riskScore.json'
import en_severity from './en/severity.json'
import en_userMenu from './en/userMenu.json'
import en_validation from './en/validation.json'
import en_webEvidence from './en/webEvidence.json'
import en_workflowStages from './en/workflowStages.json'
import vi_activity from './vi/activity.json'
import vi_actor from './vi/actor.json'
import vi_admin from './vi/admin.json'
import vi_announcements from './vi/announcements.json'
import vi_assetFreshness from './vi/assetFreshness.json'
import vi_assetCoverage from './vi/assetCoverage.json'
import vi_assetSources from './vi/assetSources.json'
import vi_assets from './vi/assets.json'
import vi_assetTimeline from './vi/assetTimeline.json'
import vi_attackSurface from './vi/attackSurface.json'
import vi_easmReview from './vi/easmReview.json'
import vi_auth from './vi/auth.json'
import vi_automations from './vi/automations.json'
import vi_common from './vi/common.json'
import vi_components from './vi/components.json'
import vi_confirm from './vi/confirm.json'
import vi_criticality from './vi/criticality.json'
import vi_findings from './vi/findings.json'
import vi_exceptions from './vi/exceptions.json'
import vi_exposures from './vi/exposures.json'
import vi_help from './vi/help.json'
import vi_insights from './vi/insights.json'
import vi_licensePolicy from './vi/licensePolicy.json'
import vi_lookalikes from './vi/lookalikes.json'
import vi_nav from './vi/nav.json'
import vi_networkSeeds from './vi/networkSeeds.json'
import vi_org from './vi/org.json'
import vi_pentest from './vi/pentest.json'
import vi_pentestCampaigns from './vi/pentestCampaigns.json'
import vi_pentestChecklists from './vi/pentestChecklists.json'
import vi_plan from './vi/plan.json'
import vi_prioritization from './vi/prioritization.json'
import vi_programs from './vi/programs.json'
import vi_remediation from './vi/remediation.json'
import vi_reports from './vi/reports.json'
import vi_scanWindows from './vi/scanWindows.json'
import vi_tenableSc from './vi/tenableSc.json'
import vi_scans from './vi/scans.json'
import vi_scope from './vi/scope.json'
import vi_sensors from './vi/sensors.json'
import vi_settings from './vi/settings.json'
import vi_riskScore from './vi/riskScore.json'
import vi_severity from './vi/severity.json'
import vi_userMenu from './vi/userMenu.json'
import vi_validation from './vi/validation.json'
import vi_webEvidence from './vi/webEvidence.json'
import vi_workflowStages from './vi/workflowStages.json'

export type Dictionary = Record<string, string>

/** Namespace name -> that namespace's catalog file, per locale. */
export const enNamespaces: Record<string, Dictionary> = {
  activity: en_activity,
  actor: en_actor,
  admin: en_admin,
  announcements: en_announcements,
  assetFreshness: en_assetFreshness,
  assetCoverage: en_assetCoverage,
  assetSources: en_assetSources,
  assets: en_assets,
  assetTimeline: en_assetTimeline,
  attackSurface: en_attackSurface,
  easmReview: en_easmReview,
  auth: en_auth,
  automations: en_automations,
  common: en_common,
  components: en_components,
  confirm: en_confirm,
  criticality: en_criticality,
  findings: en_findings,
  exceptions: en_exceptions,
  exposures: en_exposures,
  help: en_help,
  insights: en_insights,
  licensePolicy: en_licensePolicy,
  lookalikes: en_lookalikes,
  nav: en_nav,
  networkSeeds: en_networkSeeds,
  org: en_org,
  pentest: en_pentest,
  pentestCampaigns: en_pentestCampaigns,
  pentestChecklists: en_pentestChecklists,
  plan: en_plan,
  prioritization: en_prioritization,
  programs: en_programs,
  remediation: en_remediation,
  reports: en_reports,
  riskScore: en_riskScore,
  scanWindows: en_scanWindows,
  tenableSc: en_tenableSc,
  scans: en_scans,
  scope: en_scope,
  sensors: en_sensors,
  settings: en_settings,
  severity: en_severity,
  userMenu: en_userMenu,
  validation: en_validation,
  webEvidence: en_webEvidence,
  workflowStages: en_workflowStages,
}

export const viNamespaces: Record<string, Dictionary> = {
  activity: vi_activity,
  actor: vi_actor,
  admin: vi_admin,
  announcements: vi_announcements,
  assetFreshness: vi_assetFreshness,
  assetCoverage: vi_assetCoverage,
  assetSources: vi_assetSources,
  assets: vi_assets,
  assetTimeline: vi_assetTimeline,
  attackSurface: vi_attackSurface,
  easmReview: vi_easmReview,
  auth: vi_auth,
  automations: vi_automations,
  common: vi_common,
  components: vi_components,
  confirm: vi_confirm,
  criticality: vi_criticality,
  findings: vi_findings,
  exceptions: vi_exceptions,
  exposures: vi_exposures,
  help: vi_help,
  insights: vi_insights,
  licensePolicy: vi_licensePolicy,
  lookalikes: vi_lookalikes,
  nav: vi_nav,
  networkSeeds: vi_networkSeeds,
  org: vi_org,
  pentest: vi_pentest,
  pentestCampaigns: vi_pentestCampaigns,
  pentestChecklists: vi_pentestChecklists,
  plan: vi_plan,
  prioritization: vi_prioritization,
  programs: vi_programs,
  remediation: vi_remediation,
  reports: vi_reports,
  riskScore: vi_riskScore,
  scanWindows: vi_scanWindows,
  tenableSc: vi_tenableSc,
  scans: vi_scans,
  scope: vi_scope,
  sensors: vi_sensors,
  settings: vi_settings,
  severity: vi_severity,
  userMenu: vi_userMenu,
  validation: vi_validation,
  webEvidence: vi_webEvidence,
  workflowStages: vi_workflowStages,
}

const merge = (parts: Record<string, Dictionary>): Dictionary =>
  Object.assign({}, ...Object.values(parts)) as Dictionary

export const en: Dictionary = merge(enNamespaces)
export const vi: Dictionary = merge(viNamespaces)
