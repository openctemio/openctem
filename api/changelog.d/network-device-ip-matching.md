### Added: network devices are matched by address within the organization

- A reported network device (network asset of a device sub-type: firewall, router, switch, load balancer, VPN gateway, wireless controller, access point, IDS/IPS) that no identifier or exact name matched is matched to the organization's existing network device that is named by or records one of its addresses, so a device that one collector names by its hostname and another by its management address is one asset.
- The IP trust window of host matching applies; two devices with the address are ambiguous (no match, a dedup review). Segments (subnets, VLANs, …) and hosts or address assets are never matched this way, and the lookup is scoped to the organization.
