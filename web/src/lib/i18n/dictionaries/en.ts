// The English message catalog, one JSON file per namespace (see index.ts).
// Its own module so the browser loads only the active locale's catalog:
// src/lib/i18n.ts imports it on demand, and the bundler gives it its own chunk.

import en_account from './en/account.json'
import en_activity from './en/activity.json'
import en_auditLog from './en/auditLog.json'
import en_actor from './en/actor.json'
import en_admin from './en/admin.json'
import en_announcements from './en/announcements.json'
import en_assetFreshness from './en/assetFreshness.json'
import en_assetCoverage from './en/assetCoverage.json'
import en_assetPorts from './en/assetPorts.json'
import en_assetSources from './en/assetSources.json'
import en_assets from './en/assets.json'
import en_assetDetail from './en/assetDetail.json'
import en_assetGroups from './en/assetGroups.json'
import en_assetTimeline from './en/assetTimeline.json'
import en_attackSurface from './en/attackSurface.json'
import en_brand from './en/brand.json'
import en_businessContext from './en/businessContext.json'
import en_easmReview from './en/easmReview.json'
import en_threatIntel from './en/threatIntel.json'
import en_emergingThreats from './en/emergingThreats.json'
import en_auth from './en/auth.json'
import en_automations from './en/automations.json'
import en_common from './en/common.json'
import en_errors from './en/errors.json'
import en_labels from './en/labels.json'
import en_repositories from './en/repositories.json'
import en_dashboardMetrics from './en/dashboardMetrics.json'
import en_dashboardKit from './en/dashboardKit.json'
import en_dashboards from './en/dashboards.json'
import en_components from './en/components.json'
import en_credentials from './en/credentials.json'
import en_confirm from './en/confirm.json'
import en_contentCatalog from './en/contentCatalog.json'
import en_criticality from './en/criticality.json'
import en_findings from './en/findings.json'
import en_findingApprovals from './en/findingApprovals.json'
import en_findingLifecycle from './en/findingLifecycle.json'
import en_exceptions from './en/exceptions.json'
import en_exposures from './en/exposures.json'
import en_help from './en/help.json'
import en_insights from './en/insights.json'
import en_licensePolicy from './en/licensePolicy.json'
import en_notificationTypes from './en/notificationTypes.json'
import en_notifications from './en/notifications.json'
import en_notificationChannels from './en/notificationChannels.json'
import en_scmIntegration from './en/scmIntegration.json'
import en_notificationPresets from './en/notificationPresets.json'
import en_lookalikes from './en/lookalikes.json'
import en_pageMonitor from './en/pageMonitor.json'
import en_mcp from './en/mcp.json'
import en_nav from './en/nav.json'
import en_networkSeeds from './en/networkSeeds.json'
import en_org from './en/org.json'
import en_pentest from './en/pentest.json'
import en_pentestCampaigns from './en/pentestCampaigns.json'
import en_pentestChecklists from './en/pentestChecklists.json'
import en_limits from './en/limits.json'
import en_prioritization from './en/prioritization.json'
import en_programs from './en/programs.json'
import en_reports from './en/reports.json'
import en_scanWindows from './en/scanWindows.json'
import en_tenableSc from './en/tenableSc.json'
import en_siemIntegration from './en/siemIntegration.json'
import en_sla from './en/sla.json'
import en_integrationsHub from './en/integrationsHub.json'
import en_ticketMapping from './en/ticketMapping.json'
import en_importMappings from './en/importMappings.json'
import en_ticketPolicy from './en/ticketPolicy.json'
import en_ticketingIntegration from './en/ticketingIntegration.json'
import en_proxyPools from './en/proxyPools.json'
import en_wordlists from './en/wordlists.json'
import en_contentRules from './en/contentRules.json'
import en_scanApprovals from './en/scanApprovals.json'
import en_scans from './en/scans.json'
import en_scanDetail from './en/scanDetail.json'
import en_scope from './en/scope.json'
import en_scoping from './en/scoping.json'
import en_sensors from './en/sensors.json'
import en_settings from './en/settings.json'
import en_securityOverview from './en/securityOverview.json'
import en_supportAccess from './en/supportAccess.json'
import en_riskScore from './en/riskScore.json'
import en_severity from './en/severity.json'
import en_userMenu from './en/userMenu.json'
import en_validation from './en/validation.json'
import en_vulnPage from './en/vulnPage.json'
import en_webEvidence from './en/webEvidence.json'
import en_workflowStages from './en/workflowStages.json'
import en_remediationHub from './en/remediationHub.json'
import en_remediationClaim from './en/remediationClaim.json'
import en_remediationCampaigns from './en/remediationCampaigns.json'
import en_remediationQuery from './en/remediationQuery.json'
import en_myWork from './en/myWork.json'
import en_threatModel from './en/threatModel.json'
import en_attackerProfiles from './en/attackerProfiles.json'
import en_letters from './en/letters.json'
import en_crownJewels from './en/crownJewels.json'

type Dictionary = Record<string, string>

export const enNamespaces: Record<string, Dictionary> = {
  account: en_account,
  activity: en_activity,
  auditLog: en_auditLog,
  actor: en_actor,
  admin: en_admin,
  announcements: en_announcements,
  assetFreshness: en_assetFreshness,
  assetCoverage: en_assetCoverage,
  assetPorts: en_assetPorts,
  assetSources: en_assetSources,
  assets: en_assets,
  assetDetail: en_assetDetail,
  assetGroups: en_assetGroups,
  assetTimeline: en_assetTimeline,
  attackSurface: en_attackSurface,
  brand: en_brand,
  businessContext: en_businessContext,
  easmReview: en_easmReview,
  threatIntel: en_threatIntel,
  emergingThreats: en_emergingThreats,
  auth: en_auth,
  automations: en_automations,
  common: en_common,
  errors: en_errors,
  labels: en_labels,
  repositories: en_repositories,
  dashboardMetrics: en_dashboardMetrics,
  dashboardKit: en_dashboardKit,
  dashboards: en_dashboards,
  components: en_components,
  credentials: en_credentials,
  confirm: en_confirm,
  contentCatalog: en_contentCatalog,
  criticality: en_criticality,
  findings: en_findings,
  findingApprovals: en_findingApprovals,
  findingLifecycle: en_findingLifecycle,
  exceptions: en_exceptions,
  exposures: en_exposures,
  help: en_help,
  insights: en_insights,
  licensePolicy: en_licensePolicy,
  notificationTypes: en_notificationTypes,
  notifications: en_notifications,
  notificationChannels: en_notificationChannels,
  scmIntegration: en_scmIntegration,
  notificationPresets: en_notificationPresets,
  lookalikes: en_lookalikes,
  pageMonitor: en_pageMonitor,
  mcp: en_mcp,
  nav: en_nav,
  networkSeeds: en_networkSeeds,
  org: en_org,
  pentest: en_pentest,
  pentestCampaigns: en_pentestCampaigns,
  pentestChecklists: en_pentestChecklists,
  limits: en_limits,
  prioritization: en_prioritization,
  programs: en_programs,
  reports: en_reports,
  riskScore: en_riskScore,
  scanWindows: en_scanWindows,
  tenableSc: en_tenableSc,
  siemIntegration: en_siemIntegration,
  sla: en_sla,
  integrationsHub: en_integrationsHub,
  ticketMapping: en_ticketMapping,
  importMappings: en_importMappings,
  ticketPolicy: en_ticketPolicy,
  ticketingIntegration: en_ticketingIntegration,
  proxyPools: en_proxyPools,
  wordlists: en_wordlists,
  contentRules: en_contentRules,
  scanApprovals: en_scanApprovals,
  scans: en_scans,
  scanDetail: en_scanDetail,
  scope: en_scope,
  scoping: en_scoping,
  sensors: en_sensors,
  settings: en_settings,
  securityOverview: en_securityOverview,
  supportAccess: en_supportAccess,
  severity: en_severity,
  userMenu: en_userMenu,
  validation: en_validation,
  vulnPage: en_vulnPage,
  webEvidence: en_webEvidence,
  workflowStages: en_workflowStages,
  remediationHub: en_remediationHub,
  remediationClaim: en_remediationClaim,
  remediationCampaigns: en_remediationCampaigns,
  remediationQuery: en_remediationQuery,
  myWork: en_myWork,
  threatModel: en_threatModel,
  attackerProfiles: en_attackerProfiles,
  letters: en_letters,
  crownJewels: en_crownJewels,
}

export const en: Dictionary = Object.assign({}, ...Object.values(enNamespaces)) as Dictionary
