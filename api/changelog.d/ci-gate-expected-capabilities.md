### Security: the CI gate fails a run that skips an expected scan

- A repository with a coverage expectation must report every expected capability (sast, sca, secrets, iac; an empty expectation means all four) in each CI run. A run that reports no tool for one gets the blocking reason `missing_capability` ("Expected scan missing"). Before, a pull request that edited its pipeline to drop a scanner passed on silence.
- A repository without an expectation is unchanged. Tool labels are self-declared: this closes the "report nothing" path, and it does not prove that a scan ran.
