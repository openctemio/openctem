### Added: a gate policy can block dependency vulnerabilities only when a fix exists

- New gate policy option `fixable_only`, off by default, with a console switch and summary line in en and vi. With it on, a dependency or image vulnerability fails the gate on severity or EPSS only when a fixed version exists. One without a fix is listed in the verdict and pull request feedback as not blocking ("no fixed version yet"). A vulnerability on the known-exploited (KEV) list still fails; code, secret and IaC findings are not affected.
- Turning it on loosens the gate, so it needs step-up and is announced to administrators like any loosening. The strictest of several applicable policies keeps it off.
- Migration `ci_gate_fixable_only`: one boolean column with a constant default.
