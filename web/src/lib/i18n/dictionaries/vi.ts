// The Vietnamese message catalog, one JSON file per namespace (see index.ts).
// Its own module so the browser loads only the active locale's catalog:
// src/lib/i18n.ts imports it on demand, and the bundler gives it its own chunk.

import vi_account from './vi/account.json'
import vi_activity from './vi/activity.json'
import vi_auditLog from './vi/auditLog.json'
import vi_actor from './vi/actor.json'
import vi_admin from './vi/admin.json'
import vi_announcements from './vi/announcements.json'
import vi_assetFreshness from './vi/assetFreshness.json'
import vi_assetCoverage from './vi/assetCoverage.json'
import vi_assetPorts from './vi/assetPorts.json'
import vi_assetSources from './vi/assetSources.json'
import vi_assets from './vi/assets.json'
import vi_assetDetail from './vi/assetDetail.json'
import vi_assetGroups from './vi/assetGroups.json'
import vi_assetTimeline from './vi/assetTimeline.json'
import vi_attackSurface from './vi/attackSurface.json'
import vi_brand from './vi/brand.json'
import vi_businessContext from './vi/businessContext.json'
import vi_easmReview from './vi/easmReview.json'
import vi_threatIntel from './vi/threatIntel.json'
import vi_emergingThreats from './vi/emergingThreats.json'
import vi_auth from './vi/auth.json'
import vi_automations from './vi/automations.json'
import vi_common from './vi/common.json'
import vi_errors from './vi/errors.json'
import vi_labels from './vi/labels.json'
import vi_repositories from './vi/repositories.json'
import vi_dashboardMetrics from './vi/dashboardMetrics.json'
import vi_dashboardKit from './vi/dashboardKit.json'
import vi_dashboards from './vi/dashboards.json'
import vi_components from './vi/components.json'
import vi_credentials from './vi/credentials.json'
import vi_confirm from './vi/confirm.json'
import vi_contentCatalog from './vi/contentCatalog.json'
import vi_criticality from './vi/criticality.json'
import vi_findings from './vi/findings.json'
import vi_findingApprovals from './vi/findingApprovals.json'
import vi_findingLifecycle from './vi/findingLifecycle.json'
import vi_exceptions from './vi/exceptions.json'
import vi_exposures from './vi/exposures.json'
import vi_help from './vi/help.json'
import vi_insights from './vi/insights.json'
import vi_licensePolicy from './vi/licensePolicy.json'
import vi_notificationTypes from './vi/notificationTypes.json'
import vi_notifications from './vi/notifications.json'
import vi_notificationChannels from './vi/notificationChannels.json'
import vi_scmIntegration from './vi/scmIntegration.json'
import vi_notificationPresets from './vi/notificationPresets.json'
import vi_lookalikes from './vi/lookalikes.json'
import vi_mcp from './vi/mcp.json'
import vi_nav from './vi/nav.json'
import vi_networkSeeds from './vi/networkSeeds.json'
import vi_org from './vi/org.json'
import vi_pentest from './vi/pentest.json'
import vi_pentestCampaigns from './vi/pentestCampaigns.json'
import vi_pentestChecklists from './vi/pentestChecklists.json'
import vi_limits from './vi/limits.json'
import vi_prioritization from './vi/prioritization.json'
import vi_programs from './vi/programs.json'
import vi_reports from './vi/reports.json'
import vi_scanWindows from './vi/scanWindows.json'
import vi_tenableSc from './vi/tenableSc.json'
import vi_siemIntegration from './vi/siemIntegration.json'
import vi_sla from './vi/sla.json'
import vi_integrationsHub from './vi/integrationsHub.json'
import vi_ticketMapping from './vi/ticketMapping.json'
import vi_importMappings from './vi/importMappings.json'
import vi_ticketPolicy from './vi/ticketPolicy.json'
import vi_ticketingIntegration from './vi/ticketingIntegration.json'
import vi_proxyPools from './vi/proxyPools.json'
import vi_wordlists from './vi/wordlists.json'
import vi_contentRules from './vi/contentRules.json'
import vi_scanApprovals from './vi/scanApprovals.json'
import vi_scans from './vi/scans.json'
import vi_scanDetail from './vi/scanDetail.json'
import vi_scope from './vi/scope.json'
import vi_scoping from './vi/scoping.json'
import vi_sensors from './vi/sensors.json'
import vi_settings from './vi/settings.json'
import vi_securityOverview from './vi/securityOverview.json'
import vi_supportAccess from './vi/supportAccess.json'
import vi_riskScore from './vi/riskScore.json'
import vi_severity from './vi/severity.json'
import vi_userMenu from './vi/userMenu.json'
import vi_validation from './vi/validation.json'
import vi_vulnPage from './vi/vulnPage.json'
import vi_webEvidence from './vi/webEvidence.json'
import vi_workflowStages from './vi/workflowStages.json'
import vi_remediationHub from './vi/remediationHub.json'
import vi_remediationClaim from './vi/remediationClaim.json'
import vi_remediationCampaigns from './vi/remediationCampaigns.json'
import vi_remediationQuery from './vi/remediationQuery.json'
import vi_myWork from './vi/myWork.json'
import vi_threatModel from './vi/threatModel.json'
import vi_attackerProfiles from './vi/attackerProfiles.json'
import vi_letters from './vi/letters.json'
import vi_crownJewels from './vi/crownJewels.json'

type Dictionary = Record<string, string>

export const viNamespaces: Record<string, Dictionary> = {
  account: vi_account,
  activity: vi_activity,
  auditLog: vi_auditLog,
  actor: vi_actor,
  admin: vi_admin,
  announcements: vi_announcements,
  assetFreshness: vi_assetFreshness,
  assetCoverage: vi_assetCoverage,
  assetPorts: vi_assetPorts,
  assetSources: vi_assetSources,
  assets: vi_assets,
  assetDetail: vi_assetDetail,
  assetGroups: vi_assetGroups,
  assetTimeline: vi_assetTimeline,
  attackSurface: vi_attackSurface,
  brand: vi_brand,
  businessContext: vi_businessContext,
  easmReview: vi_easmReview,
  threatIntel: vi_threatIntel,
  emergingThreats: vi_emergingThreats,
  auth: vi_auth,
  automations: vi_automations,
  common: vi_common,
  errors: vi_errors,
  labels: vi_labels,
  repositories: vi_repositories,
  dashboardMetrics: vi_dashboardMetrics,
  dashboardKit: vi_dashboardKit,
  dashboards: vi_dashboards,
  components: vi_components,
  credentials: vi_credentials,
  confirm: vi_confirm,
  contentCatalog: vi_contentCatalog,
  criticality: vi_criticality,
  findings: vi_findings,
  findingApprovals: vi_findingApprovals,
  findingLifecycle: vi_findingLifecycle,
  exceptions: vi_exceptions,
  exposures: vi_exposures,
  help: vi_help,
  insights: vi_insights,
  licensePolicy: vi_licensePolicy,
  notificationTypes: vi_notificationTypes,
  notifications: vi_notifications,
  notificationChannels: vi_notificationChannels,
  scmIntegration: vi_scmIntegration,
  notificationPresets: vi_notificationPresets,
  lookalikes: vi_lookalikes,
  mcp: vi_mcp,
  nav: vi_nav,
  networkSeeds: vi_networkSeeds,
  org: vi_org,
  pentest: vi_pentest,
  pentestCampaigns: vi_pentestCampaigns,
  pentestChecklists: vi_pentestChecklists,
  limits: vi_limits,
  prioritization: vi_prioritization,
  programs: vi_programs,
  reports: vi_reports,
  riskScore: vi_riskScore,
  scanWindows: vi_scanWindows,
  tenableSc: vi_tenableSc,
  siemIntegration: vi_siemIntegration,
  sla: vi_sla,
  integrationsHub: vi_integrationsHub,
  ticketMapping: vi_ticketMapping,
  importMappings: vi_importMappings,
  ticketPolicy: vi_ticketPolicy,
  ticketingIntegration: vi_ticketingIntegration,
  proxyPools: vi_proxyPools,
  wordlists: vi_wordlists,
  contentRules: vi_contentRules,
  scanApprovals: vi_scanApprovals,
  scans: vi_scans,
  scanDetail: vi_scanDetail,
  scope: vi_scope,
  scoping: vi_scoping,
  sensors: vi_sensors,
  settings: vi_settings,
  securityOverview: vi_securityOverview,
  supportAccess: vi_supportAccess,
  severity: vi_severity,
  userMenu: vi_userMenu,
  validation: vi_validation,
  vulnPage: vi_vulnPage,
  webEvidence: vi_webEvidence,
  workflowStages: vi_workflowStages,
  remediationHub: vi_remediationHub,
  remediationClaim: vi_remediationClaim,
  remediationCampaigns: vi_remediationCampaigns,
  remediationQuery: vi_remediationQuery,
  myWork: vi_myWork,
  threatModel: vi_threatModel,
  attackerProfiles: vi_attackerProfiles,
  letters: vi_letters,
  crownJewels: vi_crownJewels,
}

export const vi: Dictionary = Object.assign({}, ...Object.values(viNamespaces)) as Dictionary
