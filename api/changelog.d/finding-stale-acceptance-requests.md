### Fixed: only accepted-risk requests expire, each with a timeline entry and an audit row

- The acceptance expiry job's sweep of stale requests (their finding had
  moved on) now expires only approved accepted-risk requests; an approved
  false-positive request that carries an end date is left alone. Each expired
  request gets an `approval_canceled` timeline entry on its finding and an
  audit row in its tenant, in the same statement.
