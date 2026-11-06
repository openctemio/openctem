package notification

import (
	"fmt"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

var (
	ErrNotificationNotFound = fmt.Errorf("%w: notification not found", shared.ErrNotFound)
)
