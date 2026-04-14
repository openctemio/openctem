-- Seed network assets for tenant "vndirect"
-- Run: psql -U openctem -d openctem -f seed_vndirect_networks.sql
-- Requires: tenant "vndirect" to exist. Replace TENANT_ID below with actual UUID.

-- Find tenant ID: SELECT id FROM tenants WHERE slug = 'vndirect';

DO $$
DECLARE
    tid UUID;
BEGIN
    SELECT id INTO tid FROM tenants WHERE slug ILIKE '%vndirect%' OR name ILIKE '%vndirect%' LIMIT 1;
    IF tid IS NULL THEN
        RAISE NOTICE 'Tenant vndirect not found, skipping seed.';
        RETURN;
    END IF;

    RAISE NOTICE 'Seeding network assets for tenant %', tid;

    -- Core Networks
    INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, scope, exposure, description, properties, tags, created_at, updated_at, first_seen, last_seen)
    VALUES
    (gen_random_uuid(), tid, 'VNDIRECT-PROD-LAN', 'network', 'critical', 'active', 'internal', 'network', 'Production LAN segment - trading systems',
     '{"network_type": "lan", "cidr": "10.10.0.0/16", "vlan_id": 100, "gateway": "10.10.0.1", "dns_servers": ["10.10.0.2", "10.10.0.3"]}'::jsonb,
     ARRAY['production', 'trading', 'critical'], NOW(), NOW(), NOW(), NOW()),

    (gen_random_uuid(), tid, 'VNDIRECT-DMZ', 'network', 'high', 'active', 'external', 'network', 'DMZ - public-facing services',
     '{"network_type": "dmz", "cidr": "172.16.0.0/24", "vlan_id": 200, "gateway": "172.16.0.1"}'::jsonb,
     ARRAY['dmz', 'public-facing'], NOW(), NOW(), NOW(), NOW()),

    (gen_random_uuid(), tid, 'VNDIRECT-MGMT', 'network', 'high', 'active', 'internal', 'network', 'Management network - infrastructure admin',
     '{"network_type": "management", "cidr": "10.20.0.0/24", "vlan_id": 300, "gateway": "10.20.0.1"}'::jsonb,
     ARRAY['management', 'infrastructure'], NOW(), NOW(), NOW(), NOW()),

    (gen_random_uuid(), tid, 'VNDIRECT-DEV', 'network', 'low', 'active', 'internal', 'network', 'Development network',
     '{"network_type": "lan", "cidr": "10.30.0.0/24", "vlan_id": 400, "gateway": "10.30.0.1"}'::jsonb,
     ARRAY['development', 'non-production'], NOW(), NOW(), NOW(), NOW()),

    (gen_random_uuid(), tid, 'VNDIRECT-BACKUP', 'network', 'medium', 'active', 'internal', 'network', 'Backup & DR network',
     '{"network_type": "backup", "cidr": "10.40.0.0/24", "vlan_id": 500, "gateway": "10.40.0.1"}'::jsonb,
     ARRAY['backup', 'disaster-recovery'], NOW(), NOW(), NOW(), NOW())

    ON CONFLICT (tenant_id, name) DO NOTHING;

    -- Firewalls
    INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, scope, exposure, description, properties, tags, created_at, updated_at, first_seen, last_seen)
    VALUES
    (gen_random_uuid(), tid, 'FW-PERIMETER-01', 'firewall', 'critical', 'active', 'external', 'network', 'Perimeter firewall - internet edge',
     '{"vendor": "Palo Alto", "model": "PA-3260", "firmware_version": "PAN-OS 11.1.2", "management_ip": "10.20.0.10", "serial_number": "PA3260-001", "ip_addresses": ["172.16.0.254", "10.10.0.254"], "interfaces": 8, "ha_mode": "active-passive"}'::jsonb,
     ARRAY['perimeter', 'critical-infrastructure', 'palo-alto'], NOW(), NOW(), NOW(), NOW()),

    (gen_random_uuid(), tid, 'FW-INTERNAL-01', 'firewall', 'high', 'active', 'internal', 'network', 'Internal segmentation firewall',
     '{"vendor": "Fortinet", "model": "FortiGate 200F", "firmware_version": "FortiOS 7.4.3", "management_ip": "10.20.0.11", "serial_number": "FGT200F-001", "ip_addresses": ["10.10.0.253", "10.30.0.253"], "interfaces": 4}'::jsonb,
     ARRAY['internal', 'segmentation', 'fortinet'], NOW(), NOW(), NOW(), NOW()),

    (gen_random_uuid(), tid, 'FW-WAF-01', 'firewall', 'high', 'active', 'external', 'network', 'Web Application Firewall',
     '{"vendor": "F5", "model": "BIG-IP ASM", "firmware_version": "16.1.4", "management_ip": "10.20.0.12", "ip_addresses": ["172.16.0.100"], "mode": "waf"}'::jsonb,
     ARRAY['waf', 'web-protection', 'f5'], NOW(), NOW(), NOW(), NOW())

    ON CONFLICT (tenant_id, name) DO NOTHING;

    -- Load Balancers
    INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, scope, exposure, description, properties, tags, created_at, updated_at, first_seen, last_seen)
    VALUES
    (gen_random_uuid(), tid, 'LB-TRADING-01', 'load_balancer', 'critical', 'active', 'internal', 'network', 'Trading platform load balancer',
     '{"vendor": "F5", "model": "BIG-IP LTM", "firmware_version": "16.1.4", "management_ip": "10.20.0.20", "vip": "10.10.1.100", "ip_addresses": ["10.10.1.100", "10.20.0.20"], "backend_count": 4, "algorithm": "round-robin"}'::jsonb,
     ARRAY['trading', 'critical', 'f5'], NOW(), NOW(), NOW(), NOW()),

    (gen_random_uuid(), tid, 'LB-WEB-01', 'load_balancer', 'high', 'active', 'external', 'network', 'Web services load balancer',
     '{"vendor": "HAProxy", "version": "2.8.5", "management_ip": "10.20.0.21", "vip": "172.16.0.50", "ip_addresses": ["172.16.0.50", "10.20.0.21"], "backend_count": 6, "algorithm": "leastconn"}'::jsonb,
     ARRAY['web', 'haproxy'], NOW(), NOW(), NOW(), NOW())

    ON CONFLICT (tenant_id, name) DO NOTHING;

    -- Network switches (as hosts with network-device tag)
    INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, scope, exposure, description, properties, tags, created_at, updated_at, first_seen, last_seen)
    VALUES
    (gen_random_uuid(), tid, 'SW-CORE-01', 'host', 'critical', 'active', 'internal', 'network', 'Core switch - datacenter backbone',
     '{"vendor": "Cisco", "model": "Catalyst 9500", "firmware_version": "IOS-XE 17.9.4", "management_ip": "10.20.0.30", "serial_number": "CAT9500-001", "ip_addresses": ["10.20.0.30"], "hostname": "SW-CORE-01", "device_role": "core_switch", "port_count": 48}'::jsonb,
     ARRAY['network-device', 'switch', 'cisco', 'core'], NOW(), NOW(), NOW(), NOW()),

    (gen_random_uuid(), tid, 'SW-ACCESS-01', 'host', 'medium', 'active', 'internal', 'network', 'Access switch - floor 1',
     '{"vendor": "Cisco", "model": "Catalyst 9300", "firmware_version": "IOS-XE 17.6.6", "management_ip": "10.20.0.31", "ip_addresses": ["10.20.0.31"], "hostname": "SW-ACCESS-01", "device_role": "access_switch", "port_count": 24}'::jsonb,
     ARRAY['network-device', 'switch', 'cisco', 'access'], NOW(), NOW(), NOW(), NOW()),

    (gen_random_uuid(), tid, 'SW-ACCESS-02', 'host', 'medium', 'active', 'internal', 'network', 'Access switch - floor 2',
     '{"vendor": "Cisco", "model": "Catalyst 9300", "firmware_version": "IOS-XE 17.6.6", "management_ip": "10.20.0.32", "ip_addresses": ["10.20.0.32"], "hostname": "SW-ACCESS-02", "device_role": "access_switch", "port_count": 24}'::jsonb,
     ARRAY['network-device', 'switch', 'cisco', 'access'], NOW(), NOW(), NOW(), NOW()),

    -- Wireless AP
    (gen_random_uuid(), tid, 'AP-OFFICE-01', 'host', 'low', 'active', 'internal', 'adjacent_network', 'Wireless access point - office area',
     '{"vendor": "Cisco", "model": "Catalyst 9120AXI", "firmware_version": "17.9.4", "management_ip": "10.20.0.40", "ip_addresses": ["10.20.0.40"], "hostname": "AP-OFFICE-01", "device_role": "wireless_ap", "ssid": ["VND-Corporate", "VND-Guest"]}'::jsonb,
     ARRAY['network-device', 'wireless', 'cisco'], NOW(), NOW(), NOW(), NOW()),

    -- Router
    (gen_random_uuid(), tid, 'RTR-WAN-01', 'host', 'critical', 'active', 'external', 'network', 'WAN router - ISP edge',
     '{"vendor": "Juniper", "model": "MX204", "firmware_version": "Junos 22.4R3", "management_ip": "10.20.0.50", "serial_number": "MX204-001", "ip_addresses": ["10.20.0.50", "203.0.113.1"], "hostname": "RTR-WAN-01", "device_role": "router", "wan_provider": "VNPT"}'::jsonb,
     ARRAY['network-device', 'router', 'juniper', 'wan'], NOW(), NOW(), NOW(), NOW())

    ON CONFLICT (tenant_id, name) DO NOTHING;

    RAISE NOTICE 'Network seed complete for tenant %', tid;
END $$;
