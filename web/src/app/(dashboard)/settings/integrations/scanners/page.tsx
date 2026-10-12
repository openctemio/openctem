'use client'

import { TENABLE_CONNECTOR_ENABLED } from '@/features/integrations/config/feature-gates'
import { ScannerImportsView } from '@/features/integrations/components/scanners/scanner-imports-view'
import { TenableConnectorView } from '@/features/integrations/components/scanners/tenable-connector-view'

/**
 * Vulnerability scanners. While the Tenable connector is paused (owner
 * decision D-14, rebuilt by RFC-047) only the .nessus import and paused rows
 * are shown; see features/integrations/config/feature-gates.ts.
 */
export default function SecurityScannersPage() {
  return TENABLE_CONNECTOR_ENABLED ? <TenableConnectorView /> : <ScannerImportsView />
}
