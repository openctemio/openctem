### Behaviour change: port scans that name no ports scan the top 1 000 ports

- The platform now names the port set of every port scan. A coverage run of `scan.ports`, a workflow port scan step and a single-tool port scan that set no `ports` or `top_n` scan the top 1 000 ports (`top_ports: 1000` in the job). Before, no setting reached the sensor and every such scan ran the sensor's own default, the top 100 ports, so the top-1 000 depth the coverage policy promised never ran.
- A set list, `top-100` or `full` is kept; the whole range still runs only when a scan sets it. Scope clamps are unchanged: names whose addresses are not in scope stay limited to the web ports, unclassified assets to the low-impact list, and port-limited program targets refuse any top list.
- A top-1 000 scan removes an open port that the same source found with the top 100 or the old default, so ports that closed leave the asset after the switch.
- Expect about ten times the probes per address on the weekly coverage scan; no sensor upgrade is needed (`top_ports` is in every supported naabu build).
