### Behaviour change: domain proof applies only to jobs on platform sensors
- With "Require a verified domain before platform sensors scan a target" on (the default on a managed service), a scan that runs on your own sensor needs no verified domain at any tier. Intrusive (T2) probes on your own sensor are governed by the scope entry's tier ceiling and the scan's approval, as before.
- A job whose targets are not proven never falls back to platform sensors: in auto mode it waits for your own sensor, and an explicit platform preference is refused.
- The scope check and the New Scan targets step say why a target is refused: platform sensors need a verified domain, or no sensor of yours can take the job.
- The "Use my own sensors" fix is offered for intrusive scans too.
