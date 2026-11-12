package notification

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var (
	ErrNotificationNotFound = fmt.Errorf("%w: notification not found", shared.ErrNotFound)
)
