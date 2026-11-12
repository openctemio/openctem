package scope

// Discovery on a scope entry (research/53 SC1): a permanent domain entry is
// also a discovery root (Certificate Transparency watches it, and the names
// found under it join the inventory, RFC-054 §4.3). This replaces the
// separate root-domain seed. A one-off entry never discovers (its names
// would never confirm), and only domain entries can.

// DiscoveryEligible reports whether the entry can discover: a domain entry
// with no expiry.
func (t *Target) DiscoveryEligible() bool {
	return (t.targetType == TargetTypeDomain || t.targetType == TargetTypeSubdomain) && t.expiresAt == nil
}

// Discovery reports whether discovery runs from the entry: switched on and
// eligible.
func (t *Target) Discovery() bool {
	return !t.discoveryOff && t.DiscoveryEligible()
}

// DiscoverySetting is the stored switch (true unless switched off), what an
// entry keeps across an expiry being set and cleared.
func (t *Target) DiscoverySetting() bool { return !t.discoveryOff }

// SetDiscovery switches discovery on or off (it runs only while eligible).
func (t *Target) SetDiscovery(on bool) { t.discoveryOff = !on }
