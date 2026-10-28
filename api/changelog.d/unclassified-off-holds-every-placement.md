### Fixed: the organization's "off" setting for unclassified assets holds on every placement

- With ownership confirmation limited to platform sensors of the hosted service, a job on the tenant's own sensors (or any job on a self-hosted install) treated unclassified assets as fully authorized even when the organization had set `unclassified_scans: off` or chose the Strict scan approval mode. Those choices now keep unclassified assets passive on every placement; `low_impact` and `full` still mean fully authorized where confirmation does not apply.
