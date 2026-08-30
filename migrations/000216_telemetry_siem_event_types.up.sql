-- SIEM / Detect-Respond ingest: give SIEM- and EDR/XDR-sourced detections
-- first-class event types on the runtime telemetry stream, instead of forcing
-- them into the 'other' catch-all. A SIEM forwarder (a "collect"-capability
-- agent) posts these to POST /api/v1/telemetry-events; the existing IOC
-- correlator matches indicator values in the event properties and auto-reopens
-- the source finding — closing the CTEM Stage-4 Detect/Respond loop for SIEM
-- data using the same proven ingest path agents already use.
--
-- Additive CHECK widening: every previously-valid value stays valid, so this
-- cannot reject any existing row.
ALTER TABLE runtime_telemetry_events DROP CONSTRAINT chk_rte_event_type;
ALTER TABLE runtime_telemetry_events ADD CONSTRAINT chk_rte_event_type CHECK (event_type IN (
    'process_start',
    'process_stop',
    'network_connect',
    'file_write',
    'file_delete',
    'dns_query',
    'auth_attempt',
    'kernel_module_load',
    'siem_detection',
    'edr_alert',
    'ioc_match',
    'other'
));
