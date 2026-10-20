### Security: `PATCH /findings/{id}/classify` is limited by finding type, needs approval to lower a risk tier, and is recorded

- A CVE can now be set only on a `vulnerability` finding. A secret, misconfiguration, compliance, web3 or license finding refuses one with `422 CLASSIFY_CVE_NOT_APPLICABLE` (it used to accept any CVE, which could make a secret a KEV/P0/critical finding).
- A change of the CVE that lowers the finding's risk tier (clearing the CVE of a KEV finding, or swapping it for one that is not in KEV, or dropping the P0 derived from it) now also needs `findings:approve`; `findings:severity` alone gets `403 CLASSIFY_LOWERS_RISK`. This closes a way around the evidence gate and the SLA that a severity downgrade does not allow.
- Every change writes a timeline entry (`metadata_updated`, `field: classification`, old and new values) and the audit action `finding.classified`. A request that changes nothing writes neither.
- **Behaviour change:** clients that sent a CVE for a non-vulnerability finding, or cleared the CVE of a KEV finding without `findings:approve`, now get an error.
