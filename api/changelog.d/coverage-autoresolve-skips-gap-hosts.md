### Fixed: a scan that left hosts uncovered no longer closes findings by absence

- Coverage auto-resolve closed open findings that a run did not repeat even when the sensor reported coverage gaps (hosts it gave up or that blocked it), unreached targets or targets its local policy refused, as long as the report said `coverage_type: full`. A finding on a host the run never finished scanning was then closed as fixed. Such a run now closes nothing (reason `uncovered_targets` in the coverage metrics). Repository scans and enforce-mode network scans are both covered.
