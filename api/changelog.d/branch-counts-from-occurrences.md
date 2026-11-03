### Fixed: Branch finding counts and branch compare follow where a finding is present

- A repository branch now counts every open finding present on it (an open occurrence on the branch), not only the findings whose headline branch it is. A finding on `main` and on a feature branch counts on both; one fixed on the feature branch counts only on `main`.
- Comparing two branches reports new, fixed and common findings by their presence on each branch. Before, a finding still present on the compared branch was reported fixed there when it was also on `main`.
- New findings by severity in a branch compare count every new finding, not only the 50 listed.
- A failed query in the branch compare returns an error instead of empty details.
