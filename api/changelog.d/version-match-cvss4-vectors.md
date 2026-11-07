### Fixed: findings with a long CVSS vector are stored again

- Every finding scored with a full CVSS 4.0 vector (up to 178 characters), or a CVSS 3.1 vector with temporal and environmental metrics, failed to store: `findings.cvss_vector` held only 100 characters. The version matcher counted these findings as failed on each pass, and scanner or pentest findings carrying such a vector failed the same way. Migration 20261107130356 widens the column to 255 characters (a catalog change, no table rewrite); the next matcher sweep stores the held findings.
- A finding the version matcher cannot store is booked on the platform's receipt with the `store_failed` code, and is retried on the organization's next reconcile. The API log names the CVE and the reason.
- The finding classify API accepts CVSS vectors up to 255 characters, and the vulnerability catalog API up to 200, matching their columns.
