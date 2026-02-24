-- =============================================================================
-- Migration 000054: Seed SPDX License Data
-- OpenCTEM OSS Edition
-- =============================================================================
-- Seeds ~200 common SPDX licenses with proper categories and risk levels.
-- Based on OSI-approved licenses and ecosystem statistics:
-- - npm: MIT dominant (~70%)
-- - Maven: Apache-2.0 dominant (~69%)
-- - PyPI: MIT (~29%), Apache-2.0 (~24%), BSD (~6%), GPL (~6%)
-- - Cargo: MIT/Apache-2.0 dual licensing common
-- - Go: BSD-3-Clause common
--
-- Sources:
-- - https://spdx.org/licenses/
-- - https://opensource.org/blog/top-open-source-licenses-in-2025
-- =============================================================================

-- =============================================================================
-- 1. PERMISSIVE LICENSES (Risk: low)
-- =============================================================================
INSERT INTO licenses (id, spdx_id, name, category, risk) VALUES
-- Most Popular (Top 10)
('MIT', 'MIT', 'MIT License', 'permissive', 'low'),
('Apache-2.0', 'Apache-2.0', 'Apache License 2.0', 'permissive', 'low'),
('BSD-3-Clause', 'BSD-3-Clause', 'BSD 3-Clause "New" or "Revised" License', 'permissive', 'low'),
('BSD-2-Clause', 'BSD-2-Clause', 'BSD 2-Clause "Simplified" License', 'permissive', 'low'),
('ISC', 'ISC', 'ISC License', 'permissive', 'low'),
('BSD-3-Clause-Clear', 'BSD-3-Clause-Clear', 'BSD 3-Clause Clear License', 'permissive', 'low'),

-- BSD Variants
('0BSD', '0BSD', 'BSD Zero Clause License', 'permissive', 'low'),
('BSD-4-Clause', 'BSD-4-Clause', 'BSD 4-Clause "Original" License', 'permissive', 'low'),
('BSD-2-Clause-Patent', 'BSD-2-Clause-Patent', 'BSD-2-Clause Plus Patent License', 'permissive', 'low'),

-- Boost/zlib/similar
('BSL-1.0', 'BSL-1.0', 'Boost Software License 1.0', 'permissive', 'low'),
('Zlib', 'Zlib', 'zlib License', 'permissive', 'low'),
('libpng-2.0', 'libpng-2.0', 'PNG Reference Library version 2', 'permissive', 'low'),

-- Unicode/X11/MIT variants
('X11', 'X11', 'X11 License', 'permissive', 'low'),
('MIT-0', 'MIT-0', 'MIT No Attribution', 'permissive', 'low'),
('NCSA', 'NCSA', 'University of Illinois/NCSA Open Source License', 'permissive', 'low'),
('Unicode-DFS-2016', 'Unicode-DFS-2016', 'Unicode License Agreement - Data Files and Software (2016)', 'permissive', 'low'),
('Unicode-3.0', 'Unicode-3.0', 'Unicode License v3', 'permissive', 'low'),

-- Language/Framework specific
('Python-2.0', 'Python-2.0', 'Python License 2.0', 'permissive', 'low'),
('PSF-2.0', 'PSF-2.0', 'Python Software Foundation License 2.0', 'permissive', 'low'),
('PHP-3.01', 'PHP-3.01', 'PHP License v3.01', 'permissive', 'low'),
('PHP-3.0', 'PHP-3.0', 'PHP License v3.0', 'permissive', 'low'),
('Ruby', 'Ruby', 'Ruby License', 'permissive', 'low'),
('Artistic-2.0', 'Artistic-2.0', 'Artistic License 2.0', 'permissive', 'low'),
('Artistic-1.0', 'Artistic-1.0', 'Artistic License 1.0', 'permissive', 'low'),
('Artistic-1.0-Perl', 'Artistic-1.0-Perl', 'Artistic License 1.0 (Perl)', 'permissive', 'low'),
('PostgreSQL', 'PostgreSQL', 'PostgreSQL License', 'permissive', 'low'),
('OpenSSL', 'OpenSSL', 'OpenSSL License', 'permissive', 'low'),
('Beerware', 'Beerware', 'Beerware License', 'permissive', 'low'),

-- Fonts
('OFL-1.0', 'OFL-1.0', 'SIL Open Font License 1.0', 'permissive', 'low'),
('OFL-1.1', 'OFL-1.1', 'SIL Open Font License 1.1', 'permissive', 'low'),
('OFL-1.1-RFN', 'OFL-1.1-RFN', 'SIL Open Font License 1.1 with Reserved Font Name', 'permissive', 'low'),
('OFL-1.1-no-RFN', 'OFL-1.1-no-RFN', 'SIL Open Font License 1.1 with no Reserved Font Name', 'permissive', 'low'),

-- Other permissive
('WTFPL', 'WTFPL', 'Do What The F*ck You Want To Public License', 'permissive', 'low'),
('Fair', 'Fair', 'Fair License', 'permissive', 'low'),
('MulanPSL-2.0', 'MulanPSL-2.0', 'Mulan Permissive Software License v2', 'permissive', 'low'),
('HPND', 'HPND', 'Historical Permission Notice and Disclaimer', 'permissive', 'low'),
('NTP', 'NTP', 'NTP License', 'permissive', 'low'),
('curl', 'curl', 'curl License', 'permissive', 'low'),
('JSON', 'JSON', 'JSON License', 'permissive', 'low'),
('Vim', 'Vim', 'Vim License', 'permissive', 'low'),
('W3C', 'W3C', 'W3C Software Notice and License (2002-12-31)', 'permissive', 'low'),
('W3C-20150513', 'W3C-20150513', 'W3C Software Notice and Document License (2015-05-13)', 'permissive', 'low'),
('Saxpath', 'Saxpath', 'Saxpath License', 'permissive', 'low'),
('SAX-PD', 'SAX-PD', 'SAX Public Domain Notice', 'permissive', 'low'),
('blessing', 'blessing', 'SQLite Blessing', 'permissive', 'low')

ON CONFLICT (spdx_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    risk = EXCLUDED.risk
WHERE licenses.category = 'unknown';

-- =============================================================================
-- 2. PUBLIC DOMAIN (Risk: low)
-- =============================================================================
INSERT INTO licenses (id, spdx_id, name, category, risk) VALUES
('Unlicense', 'Unlicense', 'The Unlicense', 'public_domain', 'low'),
('CC0-1.0', 'CC0-1.0', 'Creative Commons Zero v1.0 Universal', 'public_domain', 'low'),
('PDDL-1.0', 'PDDL-1.0', 'Open Data Commons Public Domain Dedication & License 1.0', 'public_domain', 'low')

ON CONFLICT (spdx_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    risk = EXCLUDED.risk
WHERE licenses.category = 'unknown';

-- =============================================================================
-- 3. WEAK COPYLEFT LICENSES (Risk: low)
-- =============================================================================
INSERT INTO licenses (id, spdx_id, name, category, risk) VALUES
-- LGPL family
('LGPL-2.0', 'LGPL-2.0', 'GNU Lesser General Public License v2.0', 'weak_copyleft', 'low'),
('LGPL-2.0-only', 'LGPL-2.0-only', 'GNU Lesser General Public License v2.0 only', 'weak_copyleft', 'low'),
('LGPL-2.0-or-later', 'LGPL-2.0-or-later', 'GNU Lesser General Public License v2.0 or later', 'weak_copyleft', 'low'),
('LGPL-2.0+', 'LGPL-2.0+', 'GNU Lesser General Public License v2.0 or later', 'weak_copyleft', 'low'),
('LGPL-2.1', 'LGPL-2.1', 'GNU Lesser General Public License v2.1', 'weak_copyleft', 'low'),
('LGPL-2.1-only', 'LGPL-2.1-only', 'GNU Lesser General Public License v2.1 only', 'weak_copyleft', 'low'),
('LGPL-2.1-or-later', 'LGPL-2.1-or-later', 'GNU Lesser General Public License v2.1 or later', 'weak_copyleft', 'low'),
('LGPL-2.1+', 'LGPL-2.1+', 'GNU Lesser General Public License v2.1 or later', 'weak_copyleft', 'low'),
('LGPL-3.0', 'LGPL-3.0', 'GNU Lesser General Public License v3.0', 'weak_copyleft', 'low'),
('LGPL-3.0-only', 'LGPL-3.0-only', 'GNU Lesser General Public License v3.0 only', 'weak_copyleft', 'low'),
('LGPL-3.0-or-later', 'LGPL-3.0-or-later', 'GNU Lesser General Public License v3.0 or later', 'weak_copyleft', 'low'),
('LGPL-3.0+', 'LGPL-3.0+', 'GNU Lesser General Public License v3.0 or later', 'weak_copyleft', 'low'),

-- Mozilla Public License
('MPL-1.0', 'MPL-1.0', 'Mozilla Public License 1.0', 'weak_copyleft', 'low'),
('MPL-1.1', 'MPL-1.1', 'Mozilla Public License 1.1', 'weak_copyleft', 'low'),
('MPL-2.0', 'MPL-2.0', 'Mozilla Public License 2.0', 'weak_copyleft', 'low'),
('MPL-2.0-no-copyleft-exception', 'MPL-2.0-no-copyleft-exception', 'Mozilla Public License 2.0 (no copyleft exception)', 'weak_copyleft', 'low'),

-- Eclipse Public License
('EPL-1.0', 'EPL-1.0', 'Eclipse Public License 1.0', 'weak_copyleft', 'low'),
('EPL-2.0', 'EPL-2.0', 'Eclipse Public License 2.0', 'weak_copyleft', 'low'),

-- Common Development and Distribution License
('CDDL-1.0', 'CDDL-1.0', 'Common Development and Distribution License 1.0', 'weak_copyleft', 'low'),
('CDDL-1.1', 'CDDL-1.1', 'Common Development and Distribution License 1.1', 'weak_copyleft', 'low'),

-- Common Public License
('CPL-1.0', 'CPL-1.0', 'Common Public License 1.0', 'weak_copyleft', 'low'),

-- European Union Public License
('EUPL-1.0', 'EUPL-1.0', 'European Union Public License 1.0', 'weak_copyleft', 'low'),
('EUPL-1.1', 'EUPL-1.1', 'European Union Public License 1.1', 'weak_copyleft', 'low'),
('EUPL-1.2', 'EUPL-1.2', 'European Union Public License 1.2', 'weak_copyleft', 'low'),

-- Other weak copyleft
('OSL-2.0', 'OSL-2.0', 'Open Software License 2.0', 'weak_copyleft', 'low'),
('OSL-2.1', 'OSL-2.1', 'Open Software License 2.1', 'weak_copyleft', 'low'),
('OSL-3.0', 'OSL-3.0', 'Open Software License 3.0', 'weak_copyleft', 'low'),
('MS-PL', 'MS-PL', 'Microsoft Public License', 'weak_copyleft', 'low'),
('MS-RL', 'MS-RL', 'Microsoft Reciprocal License', 'weak_copyleft', 'low'),
('IPL-1.0', 'IPL-1.0', 'IBM Public License v1.0', 'weak_copyleft', 'low'),
('IPA', 'IPA', 'IPA Font License', 'weak_copyleft', 'low'),
('LPPL-1.3c', 'LPPL-1.3c', 'LaTeX Project Public License v1.3c', 'weak_copyleft', 'low')

ON CONFLICT (spdx_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    risk = EXCLUDED.risk
WHERE licenses.category = 'unknown';

-- =============================================================================
-- 4. COPYLEFT LICENSES (Risk: medium to high)
-- =============================================================================
INSERT INTO licenses (id, spdx_id, name, category, risk) VALUES
-- GPL v2 family (Risk: medium)
('GPL-2.0', 'GPL-2.0', 'GNU General Public License v2.0', 'copyleft', 'medium'),
('GPL-2.0-only', 'GPL-2.0-only', 'GNU General Public License v2.0 only', 'copyleft', 'medium'),
('GPL-2.0-or-later', 'GPL-2.0-or-later', 'GNU General Public License v2.0 or later', 'copyleft', 'medium'),
('GPL-2.0+', 'GPL-2.0+', 'GNU General Public License v2.0 or later', 'copyleft', 'medium'),
('GPL-2.0-with-autoconf-exception', 'GPL-2.0-with-autoconf-exception', 'GNU GPL v2.0 with Autoconf exception', 'copyleft', 'medium'),
('GPL-2.0-with-bison-exception', 'GPL-2.0-with-bison-exception', 'GNU GPL v2.0 with Bison exception', 'copyleft', 'medium'),
('GPL-2.0-with-classpath-exception', 'GPL-2.0-with-classpath-exception', 'GNU GPL v2.0 with Classpath exception', 'copyleft', 'low'),
('GPL-2.0-with-font-exception', 'GPL-2.0-with-font-exception', 'GNU GPL v2.0 with Font exception', 'copyleft', 'medium'),
('GPL-2.0-with-GCC-exception', 'GPL-2.0-with-GCC-exception', 'GNU GPL v2.0 with GCC Runtime Library exception', 'copyleft', 'low'),

-- GPL v3 family (Risk: medium)
('GPL-3.0', 'GPL-3.0', 'GNU General Public License v3.0', 'copyleft', 'medium'),
('GPL-3.0-only', 'GPL-3.0-only', 'GNU General Public License v3.0 only', 'copyleft', 'medium'),
('GPL-3.0-or-later', 'GPL-3.0-or-later', 'GNU General Public License v3.0 or later', 'copyleft', 'medium'),
('GPL-3.0+', 'GPL-3.0+', 'GNU General Public License v3.0 or later', 'copyleft', 'medium'),
('GPL-3.0-with-autoconf-exception', 'GPL-3.0-with-autoconf-exception', 'GNU GPL v3.0 with Autoconf exception', 'copyleft', 'medium'),
('GPL-3.0-with-GCC-exception', 'GPL-3.0-with-GCC-exception', 'GNU GPL v3.0 with GCC Runtime Library exception', 'copyleft', 'low'),

-- GPL v1 (legacy)
('GPL-1.0', 'GPL-1.0', 'GNU General Public License v1.0', 'copyleft', 'medium'),
('GPL-1.0-only', 'GPL-1.0-only', 'GNU General Public License v1.0 only', 'copyleft', 'medium'),
('GPL-1.0-or-later', 'GPL-1.0-or-later', 'GNU General Public License v1.0 or later', 'copyleft', 'medium'),
('GPL-1.0+', 'GPL-1.0+', 'GNU General Public License v1.0 or later', 'copyleft', 'medium'),

-- AGPL family (Risk: high - network use triggers copyleft)
('AGPL-1.0', 'AGPL-1.0', 'Affero General Public License v1.0', 'copyleft', 'high'),
('AGPL-1.0-only', 'AGPL-1.0-only', 'Affero General Public License v1.0 only', 'copyleft', 'high'),
('AGPL-1.0-or-later', 'AGPL-1.0-or-later', 'Affero General Public License v1.0 or later', 'copyleft', 'high'),
('AGPL-3.0', 'AGPL-3.0', 'GNU Affero General Public License v3.0', 'copyleft', 'high'),
('AGPL-3.0-only', 'AGPL-3.0-only', 'GNU Affero General Public License v3.0 only', 'copyleft', 'high'),
('AGPL-3.0-or-later', 'AGPL-3.0-or-later', 'GNU Affero General Public License v3.0 or later', 'copyleft', 'high'),

-- Other copyleft
('CECILL-2.0', 'CECILL-2.0', 'CeCILL Free Software License Agreement v2.0', 'copyleft', 'medium'),
('CECILL-2.1', 'CECILL-2.1', 'CeCILL Free Software License Agreement v2.1', 'copyleft', 'medium'),
('CECILL-B', 'CECILL-B', 'CeCILL-B Free Software License Agreement', 'weak_copyleft', 'low'),
('CECILL-C', 'CECILL-C', 'CeCILL-C Free Software License Agreement', 'weak_copyleft', 'low'),
('Sleepycat', 'Sleepycat', 'Sleepycat License', 'copyleft', 'medium'),
('Watcom-1.0', 'Watcom-1.0', 'Sybase Open Watcom Public License 1.0', 'copyleft', 'medium'),
('RPL-1.1', 'RPL-1.1', 'Reciprocal Public License 1.1', 'copyleft', 'medium'),
('RPL-1.5', 'RPL-1.5', 'Reciprocal Public License 1.5', 'copyleft', 'medium')

ON CONFLICT (spdx_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    risk = EXCLUDED.risk
WHERE licenses.category = 'unknown';

-- =============================================================================
-- 5. CREATIVE COMMONS LICENSES
-- =============================================================================
INSERT INTO licenses (id, spdx_id, name, category, risk) VALUES
-- CC0 / Public Domain
('CC-PDDC', 'CC-PDDC', 'Creative Commons Public Domain Dedication and Certification', 'public_domain', 'low'),

-- CC-BY (Attribution only - permissive)
('CC-BY-1.0', 'CC-BY-1.0', 'Creative Commons Attribution 1.0 Generic', 'permissive', 'low'),
('CC-BY-2.0', 'CC-BY-2.0', 'Creative Commons Attribution 2.0 Generic', 'permissive', 'low'),
('CC-BY-2.5', 'CC-BY-2.5', 'Creative Commons Attribution 2.5 Generic', 'permissive', 'low'),
('CC-BY-3.0', 'CC-BY-3.0', 'Creative Commons Attribution 3.0 Unported', 'permissive', 'low'),
('CC-BY-4.0', 'CC-BY-4.0', 'Creative Commons Attribution 4.0 International', 'permissive', 'low'),

-- CC-BY-SA (ShareAlike - copyleft)
('CC-BY-SA-1.0', 'CC-BY-SA-1.0', 'Creative Commons Attribution ShareAlike 1.0 Generic', 'copyleft', 'low'),
('CC-BY-SA-2.0', 'CC-BY-SA-2.0', 'Creative Commons Attribution ShareAlike 2.0 Generic', 'copyleft', 'low'),
('CC-BY-SA-2.5', 'CC-BY-SA-2.5', 'Creative Commons Attribution ShareAlike 2.5 Generic', 'copyleft', 'low'),
('CC-BY-SA-3.0', 'CC-BY-SA-3.0', 'Creative Commons Attribution ShareAlike 3.0 Unported', 'copyleft', 'low'),
('CC-BY-SA-4.0', 'CC-BY-SA-4.0', 'Creative Commons Attribution ShareAlike 4.0 International', 'copyleft', 'low'),

-- CC-BY-NC (NonCommercial - proprietary for commercial use)
('CC-BY-NC-1.0', 'CC-BY-NC-1.0', 'Creative Commons Attribution NonCommercial 1.0 Generic', 'proprietary', 'high'),
('CC-BY-NC-2.0', 'CC-BY-NC-2.0', 'Creative Commons Attribution NonCommercial 2.0 Generic', 'proprietary', 'high'),
('CC-BY-NC-2.5', 'CC-BY-NC-2.5', 'Creative Commons Attribution NonCommercial 2.5 Generic', 'proprietary', 'high'),
('CC-BY-NC-3.0', 'CC-BY-NC-3.0', 'Creative Commons Attribution NonCommercial 3.0 Unported', 'proprietary', 'high'),
('CC-BY-NC-4.0', 'CC-BY-NC-4.0', 'Creative Commons Attribution NonCommercial 4.0 International', 'proprietary', 'high'),

-- CC-BY-NC-SA (NonCommercial ShareAlike)
('CC-BY-NC-SA-1.0', 'CC-BY-NC-SA-1.0', 'Creative Commons Attribution NonCommercial ShareAlike 1.0 Generic', 'proprietary', 'high'),
('CC-BY-NC-SA-2.0', 'CC-BY-NC-SA-2.0', 'Creative Commons Attribution NonCommercial ShareAlike 2.0 Generic', 'proprietary', 'high'),
('CC-BY-NC-SA-2.5', 'CC-BY-NC-SA-2.5', 'Creative Commons Attribution NonCommercial ShareAlike 2.5 Generic', 'proprietary', 'high'),
('CC-BY-NC-SA-3.0', 'CC-BY-NC-SA-3.0', 'Creative Commons Attribution NonCommercial ShareAlike 3.0 Unported', 'proprietary', 'high'),
('CC-BY-NC-SA-4.0', 'CC-BY-NC-SA-4.0', 'Creative Commons Attribution NonCommercial ShareAlike 4.0 International', 'proprietary', 'high'),

-- CC-BY-ND (NoDerivatives - restrictive)
('CC-BY-ND-1.0', 'CC-BY-ND-1.0', 'Creative Commons Attribution NoDerivatives 1.0 Generic', 'proprietary', 'medium'),
('CC-BY-ND-2.0', 'CC-BY-ND-2.0', 'Creative Commons Attribution NoDerivatives 2.0 Generic', 'proprietary', 'medium'),
('CC-BY-ND-2.5', 'CC-BY-ND-2.5', 'Creative Commons Attribution NoDerivatives 2.5 Generic', 'proprietary', 'medium'),
('CC-BY-ND-3.0', 'CC-BY-ND-3.0', 'Creative Commons Attribution NoDerivatives 3.0 Unported', 'proprietary', 'medium'),
('CC-BY-ND-4.0', 'CC-BY-ND-4.0', 'Creative Commons Attribution NoDerivatives 4.0 International', 'proprietary', 'medium'),

-- CC-BY-NC-ND (Most restrictive)
('CC-BY-NC-ND-1.0', 'CC-BY-NC-ND-1.0', 'Creative Commons Attribution NonCommercial NoDerivatives 1.0 Generic', 'proprietary', 'critical'),
('CC-BY-NC-ND-2.0', 'CC-BY-NC-ND-2.0', 'Creative Commons Attribution NonCommercial NoDerivatives 2.0 Generic', 'proprietary', 'critical'),
('CC-BY-NC-ND-2.5', 'CC-BY-NC-ND-2.5', 'Creative Commons Attribution NonCommercial NoDerivatives 2.5 Generic', 'proprietary', 'critical'),
('CC-BY-NC-ND-3.0', 'CC-BY-NC-ND-3.0', 'Creative Commons Attribution NonCommercial NoDerivatives 3.0 Unported', 'proprietary', 'critical'),
('CC-BY-NC-ND-4.0', 'CC-BY-NC-ND-4.0', 'Creative Commons Attribution NonCommercial NoDerivatives 4.0 International', 'proprietary', 'critical')

ON CONFLICT (spdx_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    risk = EXCLUDED.risk
WHERE licenses.category = 'unknown';

-- =============================================================================
-- 6. PROPRIETARY / SOURCE-AVAILABLE LICENSES (Risk: high to critical)
-- =============================================================================
INSERT INTO licenses (id, spdx_id, name, category, risk) VALUES
-- Business Source License
('BUSL-1.1', 'BUSL-1.1', 'Business Source License 1.1', 'proprietary', 'high'),

-- Server Side Public License
('SSPL-1.0', 'SSPL-1.0', 'Server Side Public License v1', 'proprietary', 'critical'),

-- Elastic License
('Elastic-2.0', 'Elastic-2.0', 'Elastic License 2.0', 'proprietary', 'high'),

-- Commons Clause
('Commons-Clause', 'Commons-Clause', 'Commons Clause License Condition v1.0', 'proprietary', 'high'),

-- Proprietary placeholders
('proprietary', 'proprietary', 'Proprietary License', 'proprietary', 'critical'),
('commercial', 'commercial', 'Commercial License', 'proprietary', 'high'),
('UNLICENSED', 'UNLICENSED', 'All Rights Reserved', 'proprietary', 'critical'),
('LicenseRef-LICENSE', 'LicenseRef-LICENSE', 'Custom License (see LICENSE file)', 'unknown', 'medium'),
('NOASSERTION', 'NOASSERTION', 'No License Assertion', 'unknown', 'high'),

-- Polyform licenses (source-available)
('PolyForm-Noncommercial-1.0.0', 'PolyForm-Noncommercial-1.0.0', 'PolyForm Noncommercial License 1.0.0', 'proprietary', 'high'),
('PolyForm-Small-Business-1.0.0', 'PolyForm-Small-Business-1.0.0', 'PolyForm Small Business License 1.0.0', 'proprietary', 'medium'),
('PolyForm-Free-Trial-1.0.0', 'PolyForm-Free-Trial-1.0.0', 'PolyForm Free Trial License 1.0.0', 'proprietary', 'high')

ON CONFLICT (spdx_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    risk = EXCLUDED.risk
WHERE licenses.category = 'unknown';

-- =============================================================================
-- 7. OPEN DATA LICENSES
-- =============================================================================
INSERT INTO licenses (id, spdx_id, name, category, risk) VALUES
('ODbL-1.0', 'ODbL-1.0', 'Open Data Commons Open Database License v1.0', 'copyleft', 'low'),
('ODC-By-1.0', 'ODC-By-1.0', 'Open Data Commons Attribution License v1.0', 'permissive', 'low'),
('OGL-UK-1.0', 'OGL-UK-1.0', 'Open Government Licence v1.0', 'permissive', 'low'),
('OGL-UK-2.0', 'OGL-UK-2.0', 'Open Government Licence v2.0', 'permissive', 'low'),
('OGL-UK-3.0', 'OGL-UK-3.0', 'Open Government Licence v3.0', 'permissive', 'low'),
('CDLA-Permissive-1.0', 'CDLA-Permissive-1.0', 'Community Data License Agreement Permissive 1.0', 'permissive', 'low'),
('CDLA-Permissive-2.0', 'CDLA-Permissive-2.0', 'Community Data License Agreement Permissive 2.0', 'permissive', 'low'),
('CDLA-Sharing-1.0', 'CDLA-Sharing-1.0', 'Community Data License Agreement Sharing 1.0', 'copyleft', 'low')

ON CONFLICT (spdx_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    risk = EXCLUDED.risk
WHERE licenses.category = 'unknown';

-- =============================================================================
-- 8. DOCUMENTATION LICENSES
-- =============================================================================
INSERT INTO licenses (id, spdx_id, name, category, risk) VALUES
('GFDL-1.1', 'GFDL-1.1', 'GNU Free Documentation License v1.1', 'copyleft', 'medium'),
('GFDL-1.1-only', 'GFDL-1.1-only', 'GNU Free Documentation License v1.1 only', 'copyleft', 'medium'),
('GFDL-1.1-or-later', 'GFDL-1.1-or-later', 'GNU Free Documentation License v1.1 or later', 'copyleft', 'medium'),
('GFDL-1.2', 'GFDL-1.2', 'GNU Free Documentation License v1.2', 'copyleft', 'medium'),
('GFDL-1.2-only', 'GFDL-1.2-only', 'GNU Free Documentation License v1.2 only', 'copyleft', 'medium'),
('GFDL-1.2-or-later', 'GFDL-1.2-or-later', 'GNU Free Documentation License v1.2 or later', 'copyleft', 'medium'),
('GFDL-1.3', 'GFDL-1.3', 'GNU Free Documentation License v1.3', 'copyleft', 'medium'),
('GFDL-1.3-only', 'GFDL-1.3-only', 'GNU Free Documentation License v1.3 only', 'copyleft', 'medium'),
('GFDL-1.3-or-later', 'GFDL-1.3-or-later', 'GNU Free Documentation License v1.3 or later', 'copyleft', 'medium')

ON CONFLICT (spdx_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    risk = EXCLUDED.risk
WHERE licenses.category = 'unknown';

-- =============================================================================
-- 9. UPDATE LICENSE URLs
-- =============================================================================
UPDATE licenses
SET url = 'https://spdx.org/licenses/' || spdx_id || '.html'
WHERE spdx_id IS NOT NULL
  AND spdx_id != ''
  AND (url IS NULL OR url = '');

-- Special cases
UPDATE licenses SET url = NULL WHERE spdx_id = 'proprietary';
UPDATE licenses SET url = NULL WHERE spdx_id = 'commercial';
UPDATE licenses SET url = 'https://mariadb.com/bsl11/' WHERE spdx_id = 'BUSL-1.1';
UPDATE licenses SET url = 'https://www.elastic.co/licensing/elastic-license' WHERE spdx_id = 'Elastic-2.0';
UPDATE licenses SET url = 'https://www.mongodb.com/licensing/server-side-public-license' WHERE spdx_id = 'SSPL-1.0';
UPDATE licenses SET url = 'https://polyformproject.org/licenses/noncommercial/1.0.0' WHERE spdx_id = 'PolyForm-Noncommercial-1.0.0';
UPDATE licenses SET url = 'https://polyformproject.org/licenses/small-business/1.0.0' WHERE spdx_id = 'PolyForm-Small-Business-1.0.0';
UPDATE licenses SET url = 'https://polyformproject.org/licenses/free-trial/1.0.0' WHERE spdx_id = 'PolyForm-Free-Trial-1.0.0';
