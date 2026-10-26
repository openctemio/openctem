### Added: the suggested sensor-local policy comes from your organization's scope

- A sensor in no scan zone no longer gets an empty local policy template (which admits any target outside the built-in deny list): the install commands and the sensor drawer suggest the organization's active scope (networks, addresses, domains, URL hosts) as `targets.allow`, and active network and name exclusions as `targets.deny`. A sensor in a zone keeps its zones' ranges, now with the exclusions as `deny`. Entries the sensor would refuse to load (loopback, link-local, metadata or reserved addresses) are left out and counted in the file.
- The scope is read only for a member who may read it (`attack_surface:scope:read`); others get the zones only.
- A sensor that refuses network jobs for lack of a policy shows "Suggested local policy" in its drawer: one host command that writes `/etc/openctem/sensor-policy.yaml`, then reload with SIGHUP. The platform only proposes the text; once on the host it cannot change it.
- The policy template no longer cites an internal design document or a note about sensor releases older than v0.9.0.
