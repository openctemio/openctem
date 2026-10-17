### Security: the internal entitlements API binds only a loopback or private IP

- `INTERNAL_API_ADDR` must be a loopback or private IP (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`). Every-interface, public and link-local addresses and hostnames are refused at start unless `INTERNAL_API_ALLOW_ALL_INTERFACES=true`.
