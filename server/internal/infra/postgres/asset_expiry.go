package postgres

import "github.com/openctemio/openctem/server/pkg/domain/assetlist"

// expirySQL is assetlist.ExpirySQL (alias a).
var expirySQL = assetlist.ExpirySQL

func buildExpirySQL(keys []string) string { return assetlist.BuildExpirySQL(keys) }
