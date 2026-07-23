-- Migration 000190: Seed the ONE net-new dataset for Continuous Threat Modeling
-- (RFC: docs/rfcs/RFC-continuous-threat-modeling.md — "The one net-new dataset").
--
-- ===========================================================================
-- ATTRIBUTION
-- © 2015-2024 The MITRE Corporation. This work reproduces and builds upon
-- MITRE ATT&CK®. ATT&CK is a registered trademark of The MITRE Corporation.
-- ATT&CK content is used under the MITRE ATT&CK Terms of Use and is reproduced
-- with permission. https://attack.mitre.org/  — dataset version: attack-16.1
-- ===========================================================================
--
-- This seeds a CURATED CORE (~45 common web/host/db/cloud/identity techniques),
-- NOT the full ATT&CK matrix. Two catalog tables:
--   attack_technique_mitigations : technique → MITRE M-series mitigation(s)
--   technique_applicability      : technique ↔ OpenCTEM asset-type + edge +
--                                  attacker-capability gate (OpenCTEM-authored)
--
-- Re-runnable: rows are keyed to dataset_version 'attack-16.1' and deleted
-- first so the seed is idempotent across migrate down/up cycles.

DELETE FROM attack_technique_mitigations WHERE dataset_version = 'attack-16.1';
DELETE FROM technique_applicability      WHERE dataset_version = 'attack-16.1';

-- ---------------------------------------------------------------------------
-- attack_technique_mitigations — technique → mitigation (public MITRE mapping)
-- ---------------------------------------------------------------------------
INSERT INTO attack_technique_mitigations
    (technique_id, technique_name, tactic, mitigation_id, mitigation_name, mitigation_summary, dataset_version)
VALUES
-- Reconnaissance (external attack surface)
('T1595','Active Scanning','Reconnaissance','M1056','Pre-compromise','Pre-compromise controls limiting information available to attackers.','attack-16.1'),
('T1590','Gather Victim Network Information','Reconnaissance','M1056','Pre-compromise','Pre-compromise controls limiting information available to attackers.','attack-16.1'),

-- Initial Access
('T1190','Exploit Public-Facing Application','Initial Access','M1048','Application Isolation and Sandboxing','Isolate and sandbox applications to contain exploitation.','attack-16.1'),
('T1190','Exploit Public-Facing Application','Initial Access','M1050','Exploit Protection','Enable exploit-protection features to harden against exploitation.','attack-16.1'),
('T1190','Exploit Public-Facing Application','Initial Access','M1030','Network Segmentation','Segment networks and systems to contain lateral movement.','attack-16.1'),
('T1190','Exploit Public-Facing Application','Initial Access','M1051','Update Software','Keep software patched and up to date.','attack-16.1'),
('T1190','Exploit Public-Facing Application','Initial Access','M1016','Vulnerability Scanning','Regularly scan internal and external systems for vulnerabilities and remediate.','attack-16.1'),
('T1133','External Remote Services','Initial Access','M1032','Multi-factor Authentication','Require multi-factor authentication for user and privileged access.','attack-16.1'),
('T1133','External Remote Services','Initial Access','M1035','Limit Access to Resource Over Network','Limit access to resources exposed over the network.','attack-16.1'),
('T1133','External Remote Services','Initial Access','M1030','Network Segmentation','Segment networks and systems to contain lateral movement.','attack-16.1'),
('T1133','External Remote Services','Initial Access','M1042','Disable or Remove Feature or Program','Disable or remove unneeded features, services, and programs.','attack-16.1'),
('T1078','Valid Accounts','Initial Access','M1032','Multi-factor Authentication','Require multi-factor authentication for user and privileged access.','attack-16.1'),
('T1078','Valid Accounts','Initial Access','M1027','Password Policies','Enforce strong password policies to resist guessing and cracking.','attack-16.1'),
('T1078','Valid Accounts','Initial Access','M1026','Privileged Account Management','Manage privileged accounts and enforce least privilege for admin access.','attack-16.1'),
('T1078','Valid Accounts','Initial Access','M1018','User Account Management','Manage account creation, modification, and removal to limit unauthorized use.','attack-16.1'),
('T1078','Valid Accounts','Initial Access','M1036','Account Use Policies','Set account-use policies (lockout, login hours) to limit abuse.','attack-16.1'),
('T1078.004','Valid Accounts: Cloud Accounts','Initial Access','M1032','Multi-factor Authentication','Require multi-factor authentication for user and privileged access.','attack-16.1'),
('T1078.004','Valid Accounts: Cloud Accounts','Initial Access','M1026','Privileged Account Management','Manage privileged accounts and enforce least privilege for admin access.','attack-16.1'),
('T1078.004','Valid Accounts: Cloud Accounts','Initial Access','M1018','User Account Management','Manage account creation, modification, and removal to limit unauthorized use.','attack-16.1'),
('T1199','Trusted Relationship','Initial Access','M1030','Network Segmentation','Segment networks and systems to contain lateral movement.','attack-16.1'),
('T1199','Trusted Relationship','Initial Access','M1018','User Account Management','Manage account creation, modification, and removal to limit unauthorized use.','attack-16.1'),
('T1195','Supply Chain Compromise','Initial Access','M1051','Update Software','Keep software patched and up to date.','attack-16.1'),
('T1195','Supply Chain Compromise','Initial Access','M1016','Vulnerability Scanning','Regularly scan internal and external systems for vulnerabilities and remediate.','attack-16.1'),
('T1195','Supply Chain Compromise','Initial Access','M1045','Code Signing','Enforce code signing to ensure only trusted code runs.','attack-16.1'),
('T1189','Drive-by Compromise','Initial Access','M1048','Application Isolation and Sandboxing','Isolate and sandbox applications to contain exploitation.','attack-16.1'),
('T1189','Drive-by Compromise','Initial Access','M1021','Restrict Web-Based Content','Restrict use of scripts, plugins, and active web content in browsers.','attack-16.1'),
('T1189','Drive-by Compromise','Initial Access','M1051','Update Software','Keep software patched and up to date.','attack-16.1'),
('T1566','Phishing','Initial Access','M1017','User Training','Train users to recognize social-engineering and unsafe actions.','attack-16.1'),
('T1566','Phishing','Initial Access','M1049','Antivirus/Antimalware','Deploy antivirus/antimalware to detect and quarantine threats.','attack-16.1'),
('T1566','Phishing','Initial Access','M1031','Network Intrusion Prevention','Deploy network intrusion-prevention systems to block known patterns.','attack-16.1'),
('T1566','Phishing','Initial Access','M1021','Restrict Web-Based Content','Restrict use of scripts, plugins, and active web content in browsers.','attack-16.1'),

-- Execution
('T1059','Command and Scripting Interpreter','Execution','M1038','Execution Prevention','Block execution of unauthorized or malicious code (allowlisting).','attack-16.1'),
('T1059','Command and Scripting Interpreter','Execution','M1042','Disable or Remove Feature or Program','Disable or remove unneeded features, services, and programs.','attack-16.1'),
('T1059','Command and Scripting Interpreter','Execution','M1049','Antivirus/Antimalware','Deploy antivirus/antimalware to detect and quarantine threats.','attack-16.1'),
('T1059','Command and Scripting Interpreter','Execution','M1040','Behavior Prevention on Endpoint','Enable endpoint behavior prevention to block malicious activity.','attack-16.1'),
('T1203','Exploitation for Client Execution','Execution','M1048','Application Isolation and Sandboxing','Isolate and sandbox applications to contain exploitation.','attack-16.1'),
('T1203','Exploitation for Client Execution','Execution','M1050','Exploit Protection','Enable exploit-protection features to harden against exploitation.','attack-16.1'),
('T1203','Exploitation for Client Execution','Execution','M1051','Update Software','Keep software patched and up to date.','attack-16.1'),
('T1053','Scheduled Task/Job','Execution','M1026','Privileged Account Management','Manage privileged accounts and enforce least privilege for admin access.','attack-16.1'),
('T1053','Scheduled Task/Job','Execution','M1028','Operating System Configuration','Harden operating-system configuration to reduce attack surface.','attack-16.1'),
('T1053','Scheduled Task/Job','Execution','M1047','Audit','Audit configurations, permissions, and activity to detect abuse.','attack-16.1'),
('T1204','User Execution','Execution','M1017','User Training','Train users to recognize social-engineering and unsafe actions.','attack-16.1'),
('T1204','User Execution','Execution','M1038','Execution Prevention','Block execution of unauthorized or malicious code (allowlisting).','attack-16.1'),
('T1204','User Execution','Execution','M1021','Restrict Web-Based Content','Restrict use of scripts, plugins, and active web content in browsers.','attack-16.1'),

-- Persistence
('T1098','Account Manipulation','Persistence','M1032','Multi-factor Authentication','Require multi-factor authentication for user and privileged access.','attack-16.1'),
('T1098','Account Manipulation','Persistence','M1026','Privileged Account Management','Manage privileged accounts and enforce least privilege for admin access.','attack-16.1'),
('T1098','Account Manipulation','Persistence','M1018','User Account Management','Manage account creation, modification, and removal to limit unauthorized use.','attack-16.1'),
('T1098','Account Manipulation','Persistence','M1030','Network Segmentation','Segment networks and systems to contain lateral movement.','attack-16.1'),
('T1136','Create Account','Persistence','M1032','Multi-factor Authentication','Require multi-factor authentication for user and privileged access.','attack-16.1'),
('T1136','Create Account','Persistence','M1026','Privileged Account Management','Manage privileged accounts and enforce least privilege for admin access.','attack-16.1'),
('T1136','Create Account','Persistence','M1030','Network Segmentation','Segment networks and systems to contain lateral movement.','attack-16.1'),
('T1505','Server Software Component','Persistence','M1042','Disable or Remove Feature or Program','Disable or remove unneeded features, services, and programs.','attack-16.1'),
('T1505','Server Software Component','Persistence','M1045','Code Signing','Enforce code signing to ensure only trusted code runs.','attack-16.1'),
('T1505','Server Software Component','Persistence','M1051','Update Software','Keep software patched and up to date.','attack-16.1'),
('T1505.003','Server Software Component: Web Shell','Persistence','M1049','Antivirus/Antimalware','Deploy antivirus/antimalware to detect and quarantine threats.','attack-16.1'),
('T1505.003','Server Software Component: Web Shell','Persistence','M1042','Disable or Remove Feature or Program','Disable or remove unneeded features, services, and programs.','attack-16.1'),
('T1543','Create or Modify System Process','Persistence','M1045','Code Signing','Enforce code signing to ensure only trusted code runs.','attack-16.1'),
('T1543','Create or Modify System Process','Persistence','M1022','Restrict File and Directory Permissions','Restrict file and directory permissions to prevent unauthorized access.','attack-16.1'),
('T1543','Create or Modify System Process','Persistence','M1047','Audit','Audit configurations, permissions, and activity to detect abuse.','attack-16.1'),
('T1546','Event Triggered Execution','Persistence','M1040','Behavior Prevention on Endpoint','Enable endpoint behavior prevention to block malicious activity.','attack-16.1'),
('T1546','Event Triggered Execution','Persistence','M1026','Privileged Account Management','Manage privileged accounts and enforce least privilege for admin access.','attack-16.1'),
('T1546','Event Triggered Execution','Persistence','M1047','Audit','Audit configurations, permissions, and activity to detect abuse.','attack-16.1'),

-- Privilege Escalation
('T1548','Abuse Elevation Control Mechanism','Privilege Escalation','M1026','Privileged Account Management','Manage privileged accounts and enforce least privilege for admin access.','attack-16.1'),
('T1548','Abuse Elevation Control Mechanism','Privilege Escalation','M1038','Execution Prevention','Block execution of unauthorized or malicious code (allowlisting).','attack-16.1'),
('T1548','Abuse Elevation Control Mechanism','Privilege Escalation','M1052','User Account Control','Enforce User Account Control to gate privilege elevation.','attack-16.1'),
('T1068','Exploitation for Privilege Escalation','Privilege Escalation','M1048','Application Isolation and Sandboxing','Isolate and sandbox applications to contain exploitation.','attack-16.1'),
('T1068','Exploitation for Privilege Escalation','Privilege Escalation','M1050','Exploit Protection','Enable exploit-protection features to harden against exploitation.','attack-16.1'),
('T1068','Exploitation for Privilege Escalation','Privilege Escalation','M1051','Update Software','Keep software patched and up to date.','attack-16.1'),
('T1134','Access Token Manipulation','Privilege Escalation','M1026','Privileged Account Management','Manage privileged accounts and enforce least privilege for admin access.','attack-16.1'),
('T1134','Access Token Manipulation','Privilege Escalation','M1018','User Account Management','Manage account creation, modification, and removal to limit unauthorized use.','attack-16.1'),
('T1055','Process Injection','Privilege Escalation','M1040','Behavior Prevention on Endpoint','Enable endpoint behavior prevention to block malicious activity.','attack-16.1'),
('T1055','Process Injection','Privilege Escalation','M1038','Execution Prevention','Block execution of unauthorized or malicious code (allowlisting).','attack-16.1'),

-- Defense Evasion
('T1562','Impair Defenses','Defense Evasion','M1018','User Account Management','Manage account creation, modification, and removal to limit unauthorized use.','attack-16.1'),
('T1562','Impair Defenses','Defense Evasion','M1024','Restrict Registry Permissions','Restrict registry permissions to prevent unauthorized modification.','attack-16.1'),
('T1562','Impair Defenses','Defense Evasion','M1047','Audit','Audit configurations, permissions, and activity to detect abuse.','attack-16.1'),
('T1070','Indicator Removal','Defense Evasion','M1029','Remote Data Storage','Store logs and data remotely to survive tampering on the host.','attack-16.1'),
('T1070','Indicator Removal','Defense Evasion','M1022','Restrict File and Directory Permissions','Restrict file and directory permissions to prevent unauthorized access.','attack-16.1'),
('T1027','Obfuscated Files or Information','Defense Evasion','M1049','Antivirus/Antimalware','Deploy antivirus/antimalware to detect and quarantine threats.','attack-16.1'),
('T1027','Obfuscated Files or Information','Defense Evasion','M1040','Behavior Prevention on Endpoint','Enable endpoint behavior prevention to block malicious activity.','attack-16.1'),
('T1550','Use Alternate Authentication Material','Defense Evasion','M1026','Privileged Account Management','Manage privileged accounts and enforce least privilege for admin access.','attack-16.1'),
('T1550','Use Alternate Authentication Material','Defense Evasion','M1042','Disable or Remove Feature or Program','Disable or remove unneeded features, services, and programs.','attack-16.1'),

-- Credential Access
('T1110','Brute Force','Credential Access','M1032','Multi-factor Authentication','Require multi-factor authentication for user and privileged access.','attack-16.1'),
('T1110','Brute Force','Credential Access','M1027','Password Policies','Enforce strong password policies to resist guessing and cracking.','attack-16.1'),
('T1110','Brute Force','Credential Access','M1036','Account Use Policies','Set account-use policies (lockout, login hours) to limit abuse.','attack-16.1'),
('T1110','Brute Force','Credential Access','M1018','User Account Management','Manage account creation, modification, and removal to limit unauthorized use.','attack-16.1'),
('T1552','Unsecured Credentials','Credential Access','M1041','Encrypt Sensitive Information','Encrypt sensitive data at rest and in transit.','attack-16.1'),
('T1552','Unsecured Credentials','Credential Access','M1027','Password Policies','Enforce strong password policies to resist guessing and cracking.','attack-16.1'),
('T1552','Unsecured Credentials','Credential Access','M1022','Restrict File and Directory Permissions','Restrict file and directory permissions to prevent unauthorized access.','attack-16.1'),
('T1552','Unsecured Credentials','Credential Access','M1037','Filter Network Traffic','Filter network traffic to block unauthorized ingress/egress.','attack-16.1'),
('T1552','Unsecured Credentials','Credential Access','M1047','Audit','Audit configurations, permissions, and activity to detect abuse.','attack-16.1'),
('T1555','Credentials from Password Stores','Credential Access','M1027','Password Policies','Enforce strong password policies to resist guessing and cracking.','attack-16.1'),
('T1555','Credentials from Password Stores','Credential Access','M1017','User Training','Train users to recognize social-engineering and unsafe actions.','attack-16.1'),
('T1003','OS Credential Dumping','Credential Access','M1043','Credential Access Protection','Protect stored credentials from theft and dumping.','attack-16.1'),
('T1003','OS Credential Dumping','Credential Access','M1026','Privileged Account Management','Manage privileged accounts and enforce least privilege for admin access.','attack-16.1'),
('T1003','OS Credential Dumping','Credential Access','M1028','Operating System Configuration','Harden operating-system configuration to reduce attack surface.','attack-16.1'),
('T1003','OS Credential Dumping','Credential Access','M1025','Privileged Process Integrity','Protect privileged processes from injection and tampering.','attack-16.1'),
('T1557','Adversary-in-the-Middle','Credential Access','M1041','Encrypt Sensitive Information','Encrypt sensitive data at rest and in transit.','attack-16.1'),
('T1557','Adversary-in-the-Middle','Credential Access','M1037','Filter Network Traffic','Filter network traffic to block unauthorized ingress/egress.','attack-16.1'),
('T1557','Adversary-in-the-Middle','Credential Access','M1030','Network Segmentation','Segment networks and systems to contain lateral movement.','attack-16.1'),
('T1557','Adversary-in-the-Middle','Credential Access','M1042','Disable or Remove Feature or Program','Disable or remove unneeded features, services, and programs.','attack-16.1'),

-- Discovery
('T1046','Network Service Discovery','Discovery','M1042','Disable or Remove Feature or Program','Disable or remove unneeded features, services, and programs.','attack-16.1'),
('T1046','Network Service Discovery','Discovery','M1031','Network Intrusion Prevention','Deploy network intrusion-prevention systems to block known patterns.','attack-16.1'),
('T1046','Network Service Discovery','Discovery','M1030','Network Segmentation','Segment networks and systems to contain lateral movement.','attack-16.1'),
('T1087','Account Discovery','Discovery','M1028','Operating System Configuration','Harden operating-system configuration to reduce attack surface.','attack-16.1'),

-- Lateral Movement
('T1021','Remote Services','Lateral Movement','M1032','Multi-factor Authentication','Require multi-factor authentication for user and privileged access.','attack-16.1'),
('T1021','Remote Services','Lateral Movement','M1030','Network Segmentation','Segment networks and systems to contain lateral movement.','attack-16.1'),
('T1021','Remote Services','Lateral Movement','M1035','Limit Access to Resource Over Network','Limit access to resources exposed over the network.','attack-16.1'),
('T1021','Remote Services','Lateral Movement','M1026','Privileged Account Management','Manage privileged accounts and enforce least privilege for admin access.','attack-16.1'),
('T1021.004','Remote Services: SSH','Lateral Movement','M1042','Disable or Remove Feature or Program','Disable or remove unneeded features, services, and programs.','attack-16.1'),
('T1021.004','Remote Services: SSH','Lateral Movement','M1032','Multi-factor Authentication','Require multi-factor authentication for user and privileged access.','attack-16.1'),
('T1021.004','Remote Services: SSH','Lateral Movement','M1027','Password Policies','Enforce strong password policies to resist guessing and cracking.','attack-16.1'),
('T1021.001','Remote Services: Remote Desktop Protocol','Lateral Movement','M1035','Limit Access to Resource Over Network','Limit access to resources exposed over the network.','attack-16.1'),
('T1021.001','Remote Services: Remote Desktop Protocol','Lateral Movement','M1032','Multi-factor Authentication','Require multi-factor authentication for user and privileged access.','attack-16.1'),
('T1021.001','Remote Services: Remote Desktop Protocol','Lateral Movement','M1030','Network Segmentation','Segment networks and systems to contain lateral movement.','attack-16.1'),
('T1210','Exploitation of Remote Services','Lateral Movement','M1048','Application Isolation and Sandboxing','Isolate and sandbox applications to contain exploitation.','attack-16.1'),
('T1210','Exploitation of Remote Services','Lateral Movement','M1051','Update Software','Keep software patched and up to date.','attack-16.1'),
('T1210','Exploitation of Remote Services','Lateral Movement','M1030','Network Segmentation','Segment networks and systems to contain lateral movement.','attack-16.1'),
('T1210','Exploitation of Remote Services','Lateral Movement','M1026','Privileged Account Management','Manage privileged accounts and enforce least privilege for admin access.','attack-16.1'),
('T1570','Lateral Tool Transfer','Lateral Movement','M1031','Network Intrusion Prevention','Deploy network intrusion-prevention systems to block known patterns.','attack-16.1'),
('T1570','Lateral Tool Transfer','Lateral Movement','M1037','Filter Network Traffic','Filter network traffic to block unauthorized ingress/egress.','attack-16.1'),

-- Collection
('T1005','Data from Local System','Collection','M1041','Encrypt Sensitive Information','Encrypt sensitive data at rest and in transit.','attack-16.1'),
('T1005','Data from Local System','Collection','M1057','Data Loss Prevention','Deploy data-loss-prevention controls to detect and block exfiltration.','attack-16.1'),
('T1213','Data from Information Repositories','Collection','M1018','User Account Management','Manage account creation, modification, and removal to limit unauthorized use.','attack-16.1'),
('T1213','Data from Information Repositories','Collection','M1047','Audit','Audit configurations, permissions, and activity to detect abuse.','attack-16.1'),
('T1213','Data from Information Repositories','Collection','M1041','Encrypt Sensitive Information','Encrypt sensitive data at rest and in transit.','attack-16.1'),

-- Exfiltration
('T1048','Exfiltration Over Alternative Protocol','Exfiltration','M1057','Data Loss Prevention','Deploy data-loss-prevention controls to detect and block exfiltration.','attack-16.1'),
('T1048','Exfiltration Over Alternative Protocol','Exfiltration','M1037','Filter Network Traffic','Filter network traffic to block unauthorized ingress/egress.','attack-16.1'),
('T1048','Exfiltration Over Alternative Protocol','Exfiltration','M1030','Network Segmentation','Segment networks and systems to contain lateral movement.','attack-16.1'),
('T1567','Exfiltration Over Web Service','Exfiltration','M1057','Data Loss Prevention','Deploy data-loss-prevention controls to detect and block exfiltration.','attack-16.1'),
('T1567','Exfiltration Over Web Service','Exfiltration','M1021','Restrict Web-Based Content','Restrict use of scripts, plugins, and active web content in browsers.','attack-16.1'),
('T1041','Exfiltration Over C2 Channel','Exfiltration','M1057','Data Loss Prevention','Deploy data-loss-prevention controls to detect and block exfiltration.','attack-16.1'),
('T1041','Exfiltration Over C2 Channel','Exfiltration','M1031','Network Intrusion Prevention','Deploy network intrusion-prevention systems to block known patterns.','attack-16.1'),

-- Impact
('T1486','Data Encrypted for Impact','Impact','M1053','Data Backup','Maintain regular, tested, offline data backups.','attack-16.1'),
('T1486','Data Encrypted for Impact','Impact','M1040','Behavior Prevention on Endpoint','Enable endpoint behavior prevention to block malicious activity.','attack-16.1'),
('T1485','Data Destruction','Impact','M1053','Data Backup','Maintain regular, tested, offline data backups.','attack-16.1'),
('T1498','Network Denial of Service','Impact','M1037','Filter Network Traffic','Filter network traffic to block unauthorized ingress/egress.','attack-16.1'),
('T1499','Endpoint Denial of Service','Impact','M1037','Filter Network Traffic','Filter network traffic to block unauthorized ingress/egress.','attack-16.1'),
('T1496','Resource Hijacking','Impact','M1038','Execution Prevention','Block execution of unauthorized or malicious code (allowlisting).','attack-16.1');

-- ---------------------------------------------------------------------------
-- technique_applicability — OpenCTEM-authored mapping of technique → asset-type
-- + incoming edge relationship-type + attacker-capability gate.
--   asset_type     : matches assets.asset_type taxonomy
--   edge_type      : matches attackPathRelationshipTypes (NULL = any edge)
--   min_network    : external|internal  (minimum attacker network access)
--   min_credential : none|user|admin    (minimum attacker credential level)
--   requires_persistence : technique needs a foothold with persistence
-- ---------------------------------------------------------------------------
INSERT INTO technique_applicability
    (technique_id, asset_type, edge_type, min_network, min_credential, requires_persistence, dataset_version)
VALUES
-- Public web/app entry points (exposes edge, no creds needed) — Initial Access
('T1595','website',NULL,'external','none',FALSE,'attack-16.1'),
('T1595','web_application',NULL,'external','none',FALSE,'attack-16.1'),
('T1595','domain',NULL,'external','none',FALSE,'attack-16.1'),
('T1595','subdomain',NULL,'external','none',FALSE,'attack-16.1'),
('T1595','ip_address',NULL,'external','none',FALSE,'attack-16.1'),
('T1190','website','exposes','external','none',FALSE,'attack-16.1'),
('T1190','web_application','exposes','external','none',FALSE,'attack-16.1'),
('T1190','api','exposes','external','none',FALSE,'attack-16.1'),
('T1190','application','exposes','external','none',FALSE,'attack-16.1'),
('T1190','http_service','exposes','external','none',FALSE,'attack-16.1'),
('T1190','service','exposes','external','none',FALSE,'attack-16.1'),
('T1190','host','exposes','external','none',FALSE,'attack-16.1'),
('T1133','service','exposes','external','none',FALSE,'attack-16.1'),
('T1133','host','exposes','external','none',FALSE,'attack-16.1'),
('T1133','open_port','exposes','external','none',FALSE,'attack-16.1'),
('T1189','website','exposes','external','none',FALSE,'attack-16.1'),
('T1189','web_application','exposes','external','none',FALSE,'attack-16.1'),
('T1195','repository',NULL,'external','none',FALSE,'attack-16.1'),
('T1195','container_registry',NULL,'external','none',FALSE,'attack-16.1'),
('T1199','cloud_account','has_access_to','external','user',FALSE,'attack-16.1'),
('T1199','service_account','authenticates_to','external','user',FALSE,'attack-16.1'),

-- Valid Accounts — authenticated entry / lateral (needs user creds)
('T1078','host','authenticates_to','external','user',FALSE,'attack-16.1'),
('T1078','service','authenticates_to','external','user',FALSE,'attack-16.1'),
('T1078','web_application','authenticates_to','external','user',FALSE,'attack-16.1'),
('T1078','api','authenticates_to','external','user',FALSE,'attack-16.1'),
('T1078','identity','granted_to','external','user',FALSE,'attack-16.1'),
('T1078.004','cloud_account','has_access_to','external','user',FALSE,'attack-16.1'),
('T1078.004','iam_user','granted_to','external','user',FALSE,'attack-16.1'),
('T1078.004','iam_role','granted_to','external','user',FALSE,'attack-16.1'),
('T1078.004','service_account','authenticates_to','external','user',FALSE,'attack-16.1'),

-- Brute force / credential access against exposed auth surfaces
('T1110','service','authenticates_to','external','none',FALSE,'attack-16.1'),
('T1110','host','authenticates_to','external','none',FALSE,'attack-16.1'),
('T1110','web_application','authenticates_to','external','none',FALSE,'attack-16.1'),
('T1110','api','authenticates_to','external','none',FALSE,'attack-16.1'),
('T1552','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1552','repository',NULL,'external','user',FALSE,'attack-16.1'),
('T1552','cloud_account',NULL,'internal','user',FALSE,'attack-16.1'),
('T1552','container',NULL,'internal','user',FALSE,'attack-16.1'),
('T1555','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1003','host',NULL,'internal','admin',TRUE,'attack-16.1'),
('T1557','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1557','network',NULL,'internal','user',FALSE,'attack-16.1'),

-- Execution on a reached host/container/service
('T1059','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1059','container',NULL,'internal','user',FALSE,'attack-16.1'),
('T1059','service',NULL,'internal','user',FALSE,'attack-16.1'),
('T1203','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1053','host',NULL,'internal','user',TRUE,'attack-16.1'),
('T1204','host',NULL,'external','none',FALSE,'attack-16.1'),

-- Persistence (requires a foothold with persistence)
('T1098','cloud_account','has_access_to','external','admin',TRUE,'attack-16.1'),
('T1098','iam_user','granted_to','internal','admin',TRUE,'attack-16.1'),
('T1098','service_account','authenticates_to','internal','admin',TRUE,'attack-16.1'),
('T1136','host',NULL,'internal','admin',TRUE,'attack-16.1'),
('T1136','cloud_account',NULL,'internal','admin',TRUE,'attack-16.1'),
('T1505','web_application',NULL,'external','user',TRUE,'attack-16.1'),
('T1505.003','web_application',NULL,'external','user',TRUE,'attack-16.1'),
('T1505.003','website',NULL,'external','user',TRUE,'attack-16.1'),
('T1543','host',NULL,'internal','admin',TRUE,'attack-16.1'),
('T1546','host',NULL,'internal','user',TRUE,'attack-16.1'),

-- Privilege escalation on a reached host
('T1548','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1068','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1068','container',NULL,'internal','user',FALSE,'attack-16.1'),
('T1134','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1055','host',NULL,'internal','user',FALSE,'attack-16.1'),

-- Defense evasion post-foothold
('T1562','host',NULL,'internal','admin',TRUE,'attack-16.1'),
('T1070','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1027','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1550','host',NULL,'internal','user',FALSE,'attack-16.1'),

-- Discovery from an internal foothold
('T1046','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1046','network',NULL,'internal','user',FALSE,'attack-16.1'),
('T1046','subnet',NULL,'internal','user',FALSE,'attack-16.1'),
('T1087','host',NULL,'internal','user',FALSE,'attack-16.1'),

-- Lateral movement across authenticates_to / has_access_to edges
('T1021','host','authenticates_to','internal','user',FALSE,'attack-16.1'),
('T1021.004','host','authenticates_to','internal','user',FALSE,'attack-16.1'),
('T1021.001','host','authenticates_to','internal','user',FALSE,'attack-16.1'),
('T1210','service','authenticates_to','internal','user',FALSE,'attack-16.1'),
('T1210','host','authenticates_to','internal','user',FALSE,'attack-16.1'),
('T1570','host',NULL,'internal','user',FALSE,'attack-16.1'),

-- Collection at data stores (stores_data_in edge — the crown-jewel target)
('T1005','database','stores_data_in','internal','user',FALSE,'attack-16.1'),
('T1005','data_store','stores_data_in','internal','user',FALSE,'attack-16.1'),
('T1005','host','stores_data_in','internal','user',FALSE,'attack-16.1'),
('T1005','storage','stores_data_in','internal','user',FALSE,'attack-16.1'),
('T1005','s3_bucket','stores_data_in','internal','user',FALSE,'attack-16.1'),
('T1213','database','stores_data_in','internal','user',FALSE,'attack-16.1'),
('T1213','repository','stores_data_in','internal','user',FALSE,'attack-16.1'),
('T1213','data_store','stores_data_in','internal','user',FALSE,'attack-16.1'),

-- Exfiltration from a reached data-bearing asset
('T1048','database',NULL,'internal','user',FALSE,'attack-16.1'),
('T1048','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1567','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1041','host',NULL,'internal','user',FALSE,'attack-16.1'),

-- Impact on crown-jewel data/hosts
('T1486','database',NULL,'internal','admin',FALSE,'attack-16.1'),
('T1486','host',NULL,'internal','admin',FALSE,'attack-16.1'),
('T1486','storage',NULL,'internal','admin',FALSE,'attack-16.1'),
('T1485','database',NULL,'internal','admin',FALSE,'attack-16.1'),
('T1498','website','exposes','external','none',FALSE,'attack-16.1'),
('T1498','load_balancer','exposes','external','none',FALSE,'attack-16.1'),
('T1499','web_application','exposes','external','none',FALSE,'attack-16.1'),
('T1496','host',NULL,'internal','user',FALSE,'attack-16.1'),
('T1496','compute',NULL,'internal','user',FALSE,'attack-16.1');
