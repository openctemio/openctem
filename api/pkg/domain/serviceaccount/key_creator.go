package serviceaccount

import "github.com/openctemio/openctem/api/pkg/domain/shared"

// KeyCreator is a person who minted live service-account keys in a tenant.
// A zero UserID stands for the keys that record no creator.
type KeyCreator struct {
	TenantID shared.ID
	UserID   shared.ID
}
