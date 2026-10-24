### Changed: the asset list and asset groups count only their own rows' findings

- The repository details on the asset list and the asset group list and members counted findings with a subquery grouping the findings of every organization, so each call read the whole findings index (the busiest statement under load: 30% of database time in a mixed read benchmark at 560k findings). Each read now counts the findings of the rows it returns only.
- A new database test (`TestReadQueryBudget`) holds the console's hot reads (findings, assets, asset groups, stats, dashboard, unread notifications) to a fixed number of SQL statements, for an administrator and a scoped member, whatever the data size.
