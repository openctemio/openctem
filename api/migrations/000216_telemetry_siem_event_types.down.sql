-- Roll back the SIEM/EDR/IOC event types. Relabel any rows that used the new
-- types to 'other' FIRST so the narrowed CHECK can be re-added without failing
-- — the telemetry events themselves are preserved (non-destructive rollback).
UPDATE runtime_telemetry_events
   SET event_type = 'other'
 WHERE event_type IN ('siem_detection', 'edr_alert', 'ioc_match');

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
    'other'
));
