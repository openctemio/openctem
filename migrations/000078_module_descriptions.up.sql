-- Update module descriptions to clearly explain what sidebar pages each module controls.
-- This helps tenant admins understand the impact of enabling/disabling a module.

UPDATE modules SET description = CASE id
  WHEN 'dashboard' THEN 'Main dashboard with security overview and statistics'
  WHEN 'assets' THEN 'Attack Surface, Asset Groups, Scope Config, Asset Inventory and all asset types'
  WHEN 'findings' THEN 'Findings list, Approvals, and finding management'
  WHEN 'scans' THEN 'Scans, Scanning settings (Agents, Profiles, Tools, Capabilities, Templates, Sources, Secret Store)'
  WHEN 'credentials' THEN 'Leaked credentials monitoring and detection'
  WHEN 'components' THEN 'Software Components (SBOM), Ecosystems, Licenses, and vulnerability tracking'
  WHEN 'threat_intel' THEN 'Threat Intel, Risk Analysis, and Business Impact assessment'
  WHEN 'exposures' THEN 'Exposure management and non-CVE security issues'
  WHEN 'pentest' THEN 'Penetration Testing (Campaigns, Findings, Retests, Reports), Attack Simulation, and Control Testing'
  WHEN 'remediation' THEN 'Remediation Tasks and Workflows for vulnerability remediation'
  WHEN 'reports' THEN 'Security reports and analytics'
  WHEN 'integrations' THEN 'Integrations (SCM, Notifications, CI/CD, Ticketing, SIEM)'
  WHEN 'agents' THEN 'Security scanning agents management'
  WHEN 'audit' THEN 'Audit log for tracking all actions'
  WHEN 'team' THEN 'Team members management and invitations'
  WHEN 'roles' THEN 'Custom RBAC roles and permission management'
  WHEN 'groups' THEN 'Data scope groups (Teams) for access control'
  WHEN 'settings' THEN 'General workspace settings, Risk Scoring, and Module configuration'
  WHEN 'api_keys' THEN 'API key management for programmatic access'
  WHEN 'webhooks' THEN 'Webhook configurations for external notifications'
  WHEN 'notification_settings' THEN 'Notification channel settings and delivery configuration'
  WHEN 'suppressions' THEN 'Finding suppression rules to mute known false positives'
  WHEN 'policies' THEN 'Security policies and compliance rules'
  WHEN 'sla' THEN 'SLA policies for remediation time tracking'
  WHEN 'ai_triage' THEN 'AI-powered vulnerability triage (Bulk, Auto, Workflow, BYOK, Agent modes)'
  WHEN 'pipelines' THEN 'Scan pipelines for automated scan orchestration'
  WHEN 'tools' THEN 'Security tools and capabilities management'
  ELSE description
END
WHERE id IN (
  'dashboard','assets','findings','scans','credentials','components',
  'threat_intel','exposures','pentest','remediation','reports',
  'integrations','agents','audit','team','roles','groups','settings',
  'api_keys','webhooks','notification_settings','suppressions','policies',
  'sla','ai_triage','pipelines','tools'
);
