### Fixed: release feed tests no longer fail intermittently

- The test signer for release feeds logged a signature one second before its virtual certificate began when the clock crossed a second boundary between reading the time and signing, so verification occasionally refused a good feed. The signer now signs again at the certificate start in that case, and the version check route test signs at the time of each call. Test support only; no production code or verification rule changed.
