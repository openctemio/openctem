-- =============================================
-- Compliance Framework Seed Data
-- 8 frameworks with representative controls
-- Full control lists will be expanded incrementally
-- =============================================

-- Helper: generate UUIDs deterministically from framework slug + control_id
-- Using gen_random_uuid() for all IDs

-- =============================================
-- 1. OWASP Top 10 (2021) — 10 controls
-- =============================================
INSERT INTO compliance_frameworks (id, name, slug, version, description, category, total_controls, is_system, is_active)
VALUES (
    'cf000001-0000-0000-0000-000000000001',
    'OWASP Top 10', 'owasp', '2021',
    'The OWASP Top 10 is a standard awareness document for developers and web application security representing a broad consensus about the most critical security risks to web applications.',
    'industry', 10, TRUE, TRUE
) ON CONFLICT DO NOTHING;

INSERT INTO compliance_controls (id, framework_id, control_id, title, description, category, sort_order) VALUES
('cc010001-0000-0000-0000-000000000001', 'cf000001-0000-0000-0000-000000000001', 'A01:2021', 'Broken Access Control', 'Access control enforces policy such that users cannot act outside of their intended permissions.', 'Access Control', 1),
('cc010001-0000-0000-0000-000000000002', 'cf000001-0000-0000-0000-000000000001', 'A02:2021', 'Cryptographic Failures', 'Failures related to cryptography which often lead to sensitive data exposure.', 'Cryptography', 2),
('cc010001-0000-0000-0000-000000000003', 'cf000001-0000-0000-0000-000000000001', 'A03:2021', 'Injection', 'Injection flaws such as SQL, NoSQL, OS, and LDAP injection occur when untrusted data is sent as part of a command or query.', 'Input Validation', 3),
('cc010001-0000-0000-0000-000000000004', 'cf000001-0000-0000-0000-000000000001', 'A04:2021', 'Insecure Design', 'A broad category representing different weaknesses related to design and architectural flaws.', 'Architecture', 4),
('cc010001-0000-0000-0000-000000000005', 'cf000001-0000-0000-0000-000000000001', 'A05:2021', 'Security Misconfiguration', 'Missing appropriate security hardening across any part of the application stack.', 'Configuration', 5),
('cc010001-0000-0000-0000-000000000006', 'cf000001-0000-0000-0000-000000000001', 'A06:2021', 'Vulnerable and Outdated Components', 'Components with known vulnerabilities that may undermine application defenses.', 'Dependencies', 6),
('cc010001-0000-0000-0000-000000000007', 'cf000001-0000-0000-0000-000000000001', 'A07:2021', 'Identification and Authentication Failures', 'Confirmation of identity, authentication, and session management weaknesses.', 'Authentication', 7),
('cc010001-0000-0000-0000-000000000008', 'cf000001-0000-0000-0000-000000000001', 'A08:2021', 'Software and Data Integrity Failures', 'Code and infrastructure that does not protect against integrity violations.', 'Integrity', 8),
('cc010001-0000-0000-0000-000000000009', 'cf000001-0000-0000-0000-000000000001', 'A09:2021', 'Security Logging and Monitoring Failures', 'Without logging and monitoring, breaches cannot be detected.', 'Monitoring', 9),
('cc010001-0000-0000-0000-000000000010', 'cf000001-0000-0000-0000-000000000001', 'A10:2021', 'Server-Side Request Forgery (SSRF)', 'SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.', 'Input Validation', 10)
ON CONFLICT DO NOTHING;

-- =============================================
-- 2. SOC 2 Type II (2017) — 17 trust service criteria (top-level)
-- =============================================
INSERT INTO compliance_frameworks (id, name, slug, version, description, category, total_controls, is_system, is_active)
VALUES (
    'cf000001-0000-0000-0000-000000000002',
    'SOC 2 Type II', 'soc2', '2017',
    'SOC 2 is an auditing procedure that ensures service providers securely manage data to protect the interests of the organization and the privacy of its clients.',
    'industry', 17, TRUE, TRUE
) ON CONFLICT DO NOTHING;

INSERT INTO compliance_controls (id, framework_id, control_id, title, description, category, sort_order) VALUES
('cc020001-0000-0000-0000-000000000001', 'cf000001-0000-0000-0000-000000000002', 'CC1.1', 'Control Environment', 'The entity demonstrates a commitment to integrity and ethical values.', 'Common Criteria', 1),
('cc020001-0000-0000-0000-000000000002', 'cf000001-0000-0000-0000-000000000002', 'CC1.2', 'Board Oversight', 'The board of directors demonstrates independence from management.', 'Common Criteria', 2),
('cc020001-0000-0000-0000-000000000003', 'cf000001-0000-0000-0000-000000000002', 'CC2.1', 'Information and Communication', 'The entity obtains or generates relevant, quality information.', 'Common Criteria', 3),
('cc020001-0000-0000-0000-000000000004', 'cf000001-0000-0000-0000-000000000002', 'CC3.1', 'Risk Assessment', 'The entity specifies objectives with sufficient clarity.', 'Common Criteria', 4),
('cc020001-0000-0000-0000-000000000005', 'cf000001-0000-0000-0000-000000000002', 'CC4.1', 'Monitoring Activities', 'The entity selects and develops monitoring activities.', 'Common Criteria', 5),
('cc020001-0000-0000-0000-000000000006', 'cf000001-0000-0000-0000-000000000002', 'CC5.1', 'Control Activities', 'The entity selects and develops control activities.', 'Common Criteria', 6),
('cc020001-0000-0000-0000-000000000007', 'cf000001-0000-0000-0000-000000000002', 'CC6.1', 'Logical and Physical Access Controls', 'The entity implements logical access security software and infrastructure.', 'Security', 7),
('cc020001-0000-0000-0000-000000000008', 'cf000001-0000-0000-0000-000000000002', 'CC6.2', 'User Authentication', 'Prior to issuing system credentials, the entity registers authorized users.', 'Security', 8),
('cc020001-0000-0000-0000-000000000009', 'cf000001-0000-0000-0000-000000000002', 'CC6.3', 'Access Removal', 'The entity removes access to protected information assets when appropriate.', 'Security', 9),
('cc020001-0000-0000-0000-000000000010', 'cf000001-0000-0000-0000-000000000002', 'CC6.6', 'Threat Management', 'The entity implements controls to prevent or detect and act upon threats.', 'Security', 10),
('cc020001-0000-0000-0000-000000000011', 'cf000001-0000-0000-0000-000000000002', 'CC6.7', 'Data Transmission Security', 'The entity restricts transmission of data to authorized parties.', 'Security', 11),
('cc020001-0000-0000-0000-000000000012', 'cf000001-0000-0000-0000-000000000002', 'CC6.8', 'Change Prevention', 'The entity implements controls to prevent unauthorized changes.', 'Security', 12),
('cc020001-0000-0000-0000-000000000013', 'cf000001-0000-0000-0000-000000000002', 'CC7.1', 'System Operations', 'To meet its objectives, the entity uses detection and monitoring procedures.', 'Operations', 13),
('cc020001-0000-0000-0000-000000000014', 'cf000001-0000-0000-0000-000000000002', 'CC7.2', 'Incident Response', 'The entity monitors system components and anomalies.', 'Operations', 14),
('cc020001-0000-0000-0000-000000000015', 'cf000001-0000-0000-0000-000000000002', 'CC8.1', 'Change Management', 'The entity authorizes, designs, and implements changes to infrastructure.', 'Change Management', 15),
('cc020001-0000-0000-0000-000000000016', 'cf000001-0000-0000-0000-000000000002', 'CC9.1', 'Risk Mitigation', 'The entity identifies, selects, and develops risk mitigation activities.', 'Risk Management', 16),
('cc020001-0000-0000-0000-000000000017', 'cf000001-0000-0000-0000-000000000002', 'A1.1', 'Availability', 'The entity maintains system availability consistent with objectives.', 'Availability', 17)
ON CONFLICT DO NOTHING;

-- =============================================
-- 3. ISO 27001 (2022) — 20 key controls from Annex A
-- =============================================
INSERT INTO compliance_frameworks (id, name, slug, version, description, category, total_controls, is_system, is_active)
VALUES (
    'cf000001-0000-0000-0000-000000000003',
    'ISO 27001', 'iso_27001', '2022',
    'ISO/IEC 27001 is an international standard for managing information security. It specifies requirements for establishing, implementing, maintaining, and continually improving an information security management system (ISMS).',
    'regulatory', 20, TRUE, TRUE
) ON CONFLICT DO NOTHING;

INSERT INTO compliance_controls (id, framework_id, control_id, title, description, category, sort_order) VALUES
('cc030001-0000-0000-0000-000000000001', 'cf000001-0000-0000-0000-000000000003', 'A.5.1', 'Policies for Information Security', 'A set of policies for information security shall be defined and approved.', 'Organizational', 1),
('cc030001-0000-0000-0000-000000000002', 'cf000001-0000-0000-0000-000000000003', 'A.5.2', 'Information Security Roles', 'Information security roles and responsibilities shall be defined and allocated.', 'Organizational', 2),
('cc030001-0000-0000-0000-000000000003', 'cf000001-0000-0000-0000-000000000003', 'A.5.3', 'Segregation of Duties', 'Conflicting duties and areas of responsibility shall be segregated.', 'Organizational', 3),
('cc030001-0000-0000-0000-000000000004', 'cf000001-0000-0000-0000-000000000003', 'A.6.1', 'Screening', 'Background verification checks on candidates shall be carried out.', 'People', 4),
('cc030001-0000-0000-0000-000000000005', 'cf000001-0000-0000-0000-000000000003', 'A.7.1', 'Physical Security Perimeters', 'Security perimeters shall be defined and used to protect areas.', 'Physical', 5),
('cc030001-0000-0000-0000-000000000006', 'cf000001-0000-0000-0000-000000000003', 'A.8.1', 'User Endpoint Devices', 'Information on user endpoint devices shall be protected.', 'Technological', 6),
('cc030001-0000-0000-0000-000000000007', 'cf000001-0000-0000-0000-000000000003', 'A.8.2', 'Privileged Access Rights', 'Allocation and use of privileged access rights shall be restricted.', 'Technological', 7),
('cc030001-0000-0000-0000-000000000008', 'cf000001-0000-0000-0000-000000000003', 'A.8.3', 'Information Access Restriction', 'Access to information shall be restricted in accordance with access control policy.', 'Technological', 8),
('cc030001-0000-0000-0000-000000000009', 'cf000001-0000-0000-0000-000000000003', 'A.8.5', 'Secure Authentication', 'Secure authentication technologies and procedures shall be established.', 'Technological', 9),
('cc030001-0000-0000-0000-000000000010', 'cf000001-0000-0000-0000-000000000003', 'A.8.7', 'Protection Against Malware', 'Protection against malware shall be implemented.', 'Technological', 10),
('cc030001-0000-0000-0000-000000000011', 'cf000001-0000-0000-0000-000000000003', 'A.8.8', 'Management of Technical Vulnerabilities', 'Information about technical vulnerabilities shall be obtained and evaluated.', 'Technological', 11),
('cc030001-0000-0000-0000-000000000012', 'cf000001-0000-0000-0000-000000000003', 'A.8.9', 'Configuration Management', 'Configurations shall be established, documented, and maintained.', 'Technological', 12),
('cc030001-0000-0000-0000-000000000013', 'cf000001-0000-0000-0000-000000000003', 'A.8.12', 'Data Leakage Prevention', 'Data leakage prevention measures shall be applied.', 'Technological', 13),
('cc030001-0000-0000-0000-000000000014', 'cf000001-0000-0000-0000-000000000003', 'A.8.15', 'Logging', 'Logs that record activities shall be produced and protected.', 'Technological', 14),
('cc030001-0000-0000-0000-000000000015', 'cf000001-0000-0000-0000-000000000003', 'A.8.16', 'Monitoring Activities', 'Networks, systems, and applications shall be monitored.', 'Technological', 15),
('cc030001-0000-0000-0000-000000000016', 'cf000001-0000-0000-0000-000000000003', 'A.8.20', 'Networks Security', 'Networks and network devices shall be secured.', 'Technological', 16),
('cc030001-0000-0000-0000-000000000017', 'cf000001-0000-0000-0000-000000000003', 'A.8.24', 'Use of Cryptography', 'Rules for effective use of cryptography shall be defined and implemented.', 'Technological', 17),
('cc030001-0000-0000-0000-000000000018', 'cf000001-0000-0000-0000-000000000003', 'A.8.25', 'Secure Development Life Cycle', 'Rules for secure development shall be established and applied.', 'Technological', 18),
('cc030001-0000-0000-0000-000000000019', 'cf000001-0000-0000-0000-000000000003', 'A.8.28', 'Secure Coding', 'Secure coding principles shall be applied to software development.', 'Technological', 19),
('cc030001-0000-0000-0000-000000000020', 'cf000001-0000-0000-0000-000000000003', 'A.8.34', 'Protection of Information Systems During Audit Testing', 'Audit tests and activities involving checks on operational systems shall be planned.', 'Technological', 20)
ON CONFLICT DO NOTHING;

-- =============================================
-- 4. PCI DSS (4.0) — 12 top-level requirements
-- =============================================
INSERT INTO compliance_frameworks (id, name, slug, version, description, category, total_controls, is_system, is_active)
VALUES (
    'cf000001-0000-0000-0000-000000000004',
    'PCI DSS', 'pci_dss', '4.0',
    'The Payment Card Industry Data Security Standard (PCI DSS) is a set of security standards designed to ensure that all companies that accept, process, store or transmit credit card information maintain a secure environment.',
    'regulatory', 12, TRUE, TRUE
) ON CONFLICT DO NOTHING;

INSERT INTO compliance_controls (id, framework_id, control_id, title, description, category, sort_order) VALUES
('cc040001-0000-0000-0000-000000000001', 'cf000001-0000-0000-0000-000000000004', 'Req 1', 'Install and Maintain Network Security Controls', 'Network security controls are defined and understood.', 'Network Security', 1),
('cc040001-0000-0000-0000-000000000002', 'cf000001-0000-0000-0000-000000000004', 'Req 2', 'Apply Secure Configurations to All System Components', 'Vendor-supplied defaults are changed and unnecessary functionality is removed.', 'Configuration', 2),
('cc040001-0000-0000-0000-000000000003', 'cf000001-0000-0000-0000-000000000004', 'Req 3', 'Protect Stored Account Data', 'Storage of account data is kept to a minimum. Sensitive authentication data is not stored after authorization.', 'Data Protection', 3),
('cc040001-0000-0000-0000-000000000004', 'cf000001-0000-0000-0000-000000000004', 'Req 4', 'Protect Cardholder Data with Strong Cryptography', 'Strong cryptography protects cardholder data during transmission over open, public networks.', 'Cryptography', 4),
('cc040001-0000-0000-0000-000000000005', 'cf000001-0000-0000-0000-000000000004', 'Req 5', 'Protect All Systems and Networks from Malicious Software', 'Malicious software is prevented, detected, and addressed.', 'Malware Protection', 5),
('cc040001-0000-0000-0000-000000000006', 'cf000001-0000-0000-0000-000000000004', 'Req 6', 'Develop and Maintain Secure Systems and Software', 'Bespoke and custom software are developed securely.', 'Secure Development', 6),
('cc040001-0000-0000-0000-000000000007', 'cf000001-0000-0000-0000-000000000004', 'Req 7', 'Restrict Access to System Components and Cardholder Data', 'Access to system components and cardholder data is limited to only those individuals whose jobs require such access.', 'Access Control', 7),
('cc040001-0000-0000-0000-000000000008', 'cf000001-0000-0000-0000-000000000004', 'Req 8', 'Identify Users and Authenticate Access', 'Systems and processes are used to identify users and authenticate access.', 'Authentication', 8),
('cc040001-0000-0000-0000-000000000009', 'cf000001-0000-0000-0000-000000000004', 'Req 9', 'Restrict Physical Access to Cardholder Data', 'Physical access to cardholder data and systems is restricted.', 'Physical Security', 9),
('cc040001-0000-0000-0000-000000000010', 'cf000001-0000-0000-0000-000000000004', 'Req 10', 'Log and Monitor All Access', 'All access to system components and cardholder data is logged and monitored.', 'Logging & Monitoring', 10),
('cc040001-0000-0000-0000-000000000011', 'cf000001-0000-0000-0000-000000000004', 'Req 11', 'Test Security of Systems and Networks Regularly', 'Security of systems and networks is tested regularly.', 'Testing', 11),
('cc040001-0000-0000-0000-000000000012', 'cf000001-0000-0000-0000-000000000004', 'Req 12', 'Support Information Security with Policies and Programs', 'An information security policy is maintained.', 'Governance', 12)
ON CONFLICT DO NOTHING;

-- =============================================
-- 5. NIST CSF (2.0) — 6 functions
-- =============================================
INSERT INTO compliance_frameworks (id, name, slug, version, description, category, total_controls, is_system, is_active)
VALUES (
    'cf000001-0000-0000-0000-000000000005',
    'NIST CSF', 'nist', '2.0',
    'The NIST Cybersecurity Framework provides a policy framework of computer security guidance for how organizations can assess and improve their ability to prevent, detect, and respond to cyber attacks.',
    'best_practice', 6, TRUE, TRUE
) ON CONFLICT DO NOTHING;

INSERT INTO compliance_controls (id, framework_id, control_id, title, description, category, sort_order) VALUES
('cc050001-0000-0000-0000-000000000001', 'cf000001-0000-0000-0000-000000000005', 'GV', 'Govern', 'The organizations cybersecurity risk management strategy, expectations, and policy are established, communicated, and monitored.', 'Governance', 1),
('cc050001-0000-0000-0000-000000000002', 'cf000001-0000-0000-0000-000000000005', 'ID', 'Identify', 'The organizations current cybersecurity risks are understood.', 'Identification', 2),
('cc050001-0000-0000-0000-000000000003', 'cf000001-0000-0000-0000-000000000005', 'PR', 'Protect', 'Safeguards to manage the organizations cybersecurity risks are used.', 'Protection', 3),
('cc050001-0000-0000-0000-000000000004', 'cf000001-0000-0000-0000-000000000005', 'DE', 'Detect', 'Possible cybersecurity attacks and compromises are found and analyzed.', 'Detection', 4),
('cc050001-0000-0000-0000-000000000005', 'cf000001-0000-0000-0000-000000000005', 'RS', 'Respond', 'Actions regarding a detected cybersecurity incident are taken.', 'Response', 5),
('cc050001-0000-0000-0000-000000000006', 'cf000001-0000-0000-0000-000000000005', 'RC', 'Recover', 'Assets and operations affected by a cybersecurity incident are restored.', 'Recovery', 6)
ON CONFLICT DO NOTHING;

-- =============================================
-- 6. HIPAA (2013) — 10 key safeguards
-- =============================================
INSERT INTO compliance_frameworks (id, name, slug, version, description, category, total_controls, is_system, is_active)
VALUES (
    'cf000001-0000-0000-0000-000000000006',
    'HIPAA', 'hipaa', '2013',
    'The Health Insurance Portability and Accountability Act sets national standards for protecting sensitive patient health information from being disclosed without the patients consent or knowledge.',
    'regulatory', 10, TRUE, TRUE
) ON CONFLICT DO NOTHING;

INSERT INTO compliance_controls (id, framework_id, control_id, title, description, category, sort_order) VALUES
('cc060001-0000-0000-0000-000000000001', 'cf000001-0000-0000-0000-000000000006', '164.308(a)(1)', 'Security Management Process', 'Implement policies and procedures to prevent, detect, contain, and correct security violations.', 'Administrative', 1),
('cc060001-0000-0000-0000-000000000002', 'cf000001-0000-0000-0000-000000000006', '164.308(a)(3)', 'Workforce Security', 'Implement policies and procedures to ensure members of the workforce have appropriate access.', 'Administrative', 2),
('cc060001-0000-0000-0000-000000000003', 'cf000001-0000-0000-0000-000000000006', '164.308(a)(4)', 'Information Access Management', 'Implement policies and procedures for authorizing access to ePHI.', 'Administrative', 3),
('cc060001-0000-0000-0000-000000000004', 'cf000001-0000-0000-0000-000000000006', '164.308(a)(5)', 'Security Awareness and Training', 'Implement a security awareness and training program for all members of the workforce.', 'Administrative', 4),
('cc060001-0000-0000-0000-000000000005', 'cf000001-0000-0000-0000-000000000006', '164.308(a)(6)', 'Security Incident Procedures', 'Implement policies and procedures to address security incidents.', 'Administrative', 5),
('cc060001-0000-0000-0000-000000000006', 'cf000001-0000-0000-0000-000000000006', '164.310(a)(1)', 'Facility Access Controls', 'Implement policies and procedures to limit physical access.', 'Physical', 6),
('cc060001-0000-0000-0000-000000000007', 'cf000001-0000-0000-0000-000000000006', '164.312(a)(1)', 'Access Control', 'Implement technical policies and procedures for computing systems that maintain ePHI.', 'Technical', 7),
('cc060001-0000-0000-0000-000000000008', 'cf000001-0000-0000-0000-000000000006', '164.312(b)', 'Audit Controls', 'Implement mechanisms to record and examine activity in systems containing ePHI.', 'Technical', 8),
('cc060001-0000-0000-0000-000000000009', 'cf000001-0000-0000-0000-000000000006', '164.312(c)(1)', 'Integrity', 'Implement policies and procedures to protect ePHI from improper alteration or destruction.', 'Technical', 9),
('cc060001-0000-0000-0000-000000000010', 'cf000001-0000-0000-0000-000000000006', '164.312(e)(1)', 'Transmission Security', 'Implement technical security measures to guard against unauthorized access to ePHI during transmission.', 'Technical', 10)
ON CONFLICT DO NOTHING;

-- =============================================
-- 7. GDPR (2016) — 10 key articles
-- =============================================
INSERT INTO compliance_frameworks (id, name, slug, version, description, category, total_controls, is_system, is_active)
VALUES (
    'cf000001-0000-0000-0000-000000000007',
    'GDPR', 'gdpr', '2016',
    'The General Data Protection Regulation is a regulation in EU law on data protection and privacy for all individuals within the European Union and the European Economic Area.',
    'regulatory', 10, TRUE, TRUE
) ON CONFLICT DO NOTHING;

INSERT INTO compliance_controls (id, framework_id, control_id, title, description, category, sort_order) VALUES
('cc070001-0000-0000-0000-000000000001', 'cf000001-0000-0000-0000-000000000007', 'Art. 5', 'Principles Relating to Processing', 'Personal data shall be processed lawfully, fairly, and in a transparent manner.', 'Data Processing', 1),
('cc070001-0000-0000-0000-000000000002', 'cf000001-0000-0000-0000-000000000007', 'Art. 6', 'Lawfulness of Processing', 'Processing shall be lawful only if the data subject has given consent.', 'Data Processing', 2),
('cc070001-0000-0000-0000-000000000003', 'cf000001-0000-0000-0000-000000000007', 'Art. 17', 'Right to Erasure', 'The data subject shall have the right to obtain erasure of personal data.', 'Data Subject Rights', 3),
('cc070001-0000-0000-0000-000000000004', 'cf000001-0000-0000-0000-000000000007', 'Art. 25', 'Data Protection by Design and Default', 'The controller shall implement appropriate technical and organisational measures.', 'Data Protection', 4),
('cc070001-0000-0000-0000-000000000005', 'cf000001-0000-0000-0000-000000000007', 'Art. 30', 'Records of Processing Activities', 'Each controller shall maintain a record of processing activities.', 'Accountability', 5),
('cc070001-0000-0000-0000-000000000006', 'cf000001-0000-0000-0000-000000000007', 'Art. 32', 'Security of Processing', 'The controller and processor shall implement appropriate technical and organisational security measures.', 'Security', 6),
('cc070001-0000-0000-0000-000000000007', 'cf000001-0000-0000-0000-000000000007', 'Art. 33', 'Notification of Breach to Authority', 'In case of a personal data breach, the controller shall notify the supervisory authority within 72 hours.', 'Breach Notification', 7),
('cc070001-0000-0000-0000-000000000008', 'cf000001-0000-0000-0000-000000000007', 'Art. 34', 'Communication of Breach to Data Subject', 'When the breach is likely to result in a high risk, the controller shall communicate the breach.', 'Breach Notification', 8),
('cc070001-0000-0000-0000-000000000009', 'cf000001-0000-0000-0000-000000000007', 'Art. 35', 'Data Protection Impact Assessment', 'Where processing is likely to result in a high risk, the controller shall carry out an assessment.', 'Risk Assessment', 9),
('cc070001-0000-0000-0000-000000000010', 'cf000001-0000-0000-0000-000000000007', 'Art. 37', 'Designation of Data Protection Officer', 'The controller and processor shall designate a data protection officer.', 'Governance', 10)
ON CONFLICT DO NOTHING;

-- =============================================
-- 8. CIS Controls (8.0) — 18 top-level controls
-- =============================================
INSERT INTO compliance_frameworks (id, name, slug, version, description, category, total_controls, is_system, is_active)
VALUES (
    'cf000001-0000-0000-0000-000000000008',
    'CIS Controls', 'cis', '8.0',
    'The CIS Critical Security Controls are a prioritized set of actions that collectively form a defense-in-depth set of best practices that mitigate the most common attacks against systems and networks.',
    'best_practice', 18, TRUE, TRUE
) ON CONFLICT DO NOTHING;

INSERT INTO compliance_controls (id, framework_id, control_id, title, description, category, sort_order) VALUES
('cc080001-0000-0000-0000-000000000001', 'cf000001-0000-0000-0000-000000000008', 'CIS 1', 'Inventory and Control of Enterprise Assets', 'Actively manage all enterprise assets connected to the infrastructure.', 'Asset Management', 1),
('cc080001-0000-0000-0000-000000000002', 'cf000001-0000-0000-0000-000000000008', 'CIS 2', 'Inventory and Control of Software Assets', 'Actively manage all software on the network.', 'Software Management', 2),
('cc080001-0000-0000-0000-000000000003', 'cf000001-0000-0000-0000-000000000008', 'CIS 3', 'Data Protection', 'Develop processes and technical controls to identify and protect data.', 'Data Protection', 3),
('cc080001-0000-0000-0000-000000000004', 'cf000001-0000-0000-0000-000000000008', 'CIS 4', 'Secure Configuration of Enterprise Assets and Software', 'Establish and maintain secure configuration.', 'Configuration', 4),
('cc080001-0000-0000-0000-000000000005', 'cf000001-0000-0000-0000-000000000008', 'CIS 5', 'Account Management', 'Use processes and tools to assign and manage authorization.', 'Access Control', 5),
('cc080001-0000-0000-0000-000000000006', 'cf000001-0000-0000-0000-000000000008', 'CIS 6', 'Access Control Management', 'Use processes and tools to create, assign, manage, and revoke access.', 'Access Control', 6),
('cc080001-0000-0000-0000-000000000007', 'cf000001-0000-0000-0000-000000000008', 'CIS 7', 'Continuous Vulnerability Management', 'Develop a plan to continuously assess and track vulnerabilities.', 'Vulnerability Management', 7),
('cc080001-0000-0000-0000-000000000008', 'cf000001-0000-0000-0000-000000000008', 'CIS 8', 'Audit Log Management', 'Collect, alert, review, and retain audit logs.', 'Logging', 8),
('cc080001-0000-0000-0000-000000000009', 'cf000001-0000-0000-0000-000000000008', 'CIS 9', 'Email and Web Browser Protections', 'Improve protections and detections of email and web threats.', 'Endpoint Protection', 9),
('cc080001-0000-0000-0000-000000000010', 'cf000001-0000-0000-0000-000000000008', 'CIS 10', 'Malware Defenses', 'Prevent or control installation and execution of malicious applications.', 'Malware Protection', 10),
('cc080001-0000-0000-0000-000000000011', 'cf000001-0000-0000-0000-000000000008', 'CIS 11', 'Data Recovery', 'Establish and maintain data recovery practices.', 'Recovery', 11),
('cc080001-0000-0000-0000-000000000012', 'cf000001-0000-0000-0000-000000000008', 'CIS 12', 'Network Infrastructure Management', 'Establish and maintain the secure configuration of network infrastructure.', 'Network Security', 12),
('cc080001-0000-0000-0000-000000000013', 'cf000001-0000-0000-0000-000000000008', 'CIS 13', 'Network Monitoring and Defense', 'Operate processes and tooling to establish and maintain comprehensive network monitoring.', 'Monitoring', 13),
('cc080001-0000-0000-0000-000000000014', 'cf000001-0000-0000-0000-000000000008', 'CIS 14', 'Security Awareness and Skills Training', 'Establish and maintain a security awareness program.', 'Training', 14),
('cc080001-0000-0000-0000-000000000015', 'cf000001-0000-0000-0000-000000000008', 'CIS 15', 'Service Provider Management', 'Develop a process to evaluate service providers.', 'Third Party', 15),
('cc080001-0000-0000-0000-000000000016', 'cf000001-0000-0000-0000-000000000008', 'CIS 16', 'Application Software Security', 'Manage the security life cycle of software.', 'Application Security', 16),
('cc080001-0000-0000-0000-000000000017', 'cf000001-0000-0000-0000-000000000008', 'CIS 17', 'Incident Response Management', 'Establish a program to develop and maintain an incident response capability.', 'Incident Response', 17),
('cc080001-0000-0000-0000-000000000018', 'cf000001-0000-0000-0000-000000000008', 'CIS 18', 'Penetration Testing', 'Test the effectiveness and resiliency of enterprise assets through penetration testing.', 'Testing', 18)
ON CONFLICT DO NOTHING;
