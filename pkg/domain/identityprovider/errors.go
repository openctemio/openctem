package identityprovider

import "errors"

var (
	ErrNotFound          = errors.New("identity provider not found")
	ErrAlreadyExists     = errors.New("identity provider already configured for this tenant")
	ErrInvalidProvider   = errors.New("invalid identity provider type")
	ErrDomainNotAllowed  = errors.New("email domain not allowed for this identity provider")
	ErrProviderInactive  = errors.New("identity provider is not active")
	ErrInvalidConfig     = errors.New("invalid identity provider configuration")
)
