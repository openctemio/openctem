package postgres

import "github.com/openctemio/openctem/server/pkg/domain/assetlist"

// The assets list filter on whether a host name resolves.

// assetResolutionCondition is assetlist.ResolutionSQL (alias a).
func assetResolutionCondition(value string) string { return assetlist.ResolutionSQL(value) }
