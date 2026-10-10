### Added: passive RDAP and ASN lookups in the Passive discovery workflow

- New T0 scan stages `lookup.rdap` (registrar, registrant organization, name servers and registration dates of a root domain, from its registry's RDAP service) and `lookup.asn` (origin autonomous system, holder and announced range of an address or network, from the public-domain IPtoASN dataset), run by the sensor's built-in `rdap` and `asn` tools. Both declare the `egress-proxy` network: they never send anything to the target hosts, so a passive scan may run them.
- Migration `001965_passive_lookup_tools`: platform tool rows `rdap` and `asn`, and two steps in the "Passive discovery" starter template (RDAP lookup of the roots, ASN lookup of the resolved addresses; template version 2). Tenant copies made earlier keep their steps.
- A network a sensor report creates (the ranges an autonomous system announces) gets an attribution record like an internet-facing name: needs_review from a scan, candidate from an unsolicited report. Existing networks are unchanged.
- `rdap` and `asn` are built-in sensor tools for the tool-trust check.
- ctis is pinned to the commit with `lookup.rdap@1` and `lookup.asn@1`.
- **Upgrade note:** needs a sensor with the `rdap` and `asn` tools (sensor PR "passive rdap and asn tools"). Until a sensor that has them is online, the two new steps of a Passive discovery run wait and then time out; the other steps run as before.
