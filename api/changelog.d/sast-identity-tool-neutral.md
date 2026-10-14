### Behaviour change: a SAST finding is keyed on the code it flags, not on the engine

- The SAST identity no longer uses the tool name or the engine's own fingerprints (SARIF `primaryLocationLineHash`, Semgrep `matchBasedId/v1`). It is the rule, the repository path and the hash of the flagged code, from the snippet or from the producer's CTIS `snippetHash/v1`. Running the same rules on another engine keeps every finding and its triage, and a job that forges an engine fingerprint can no longer take over a finding marked false positive.
- A finding without its code is keyed on its start line, computed by the platform, instead of the producer's own fingerprint. The first report that carries the code re-keys it to the code key; its status and history stay.
- A SARIF finding with no snippet now gets a new finding when its line moves. Producers should include the region snippet, or the `snippetHash/v1` partial fingerprint.
