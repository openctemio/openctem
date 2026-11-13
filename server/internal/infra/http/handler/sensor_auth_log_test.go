package handler

import (
	"errors"
	"fmt"
	"testing"
)

func TestSensorAuthFailureReasonNeverEchoesTheError(t *testing.T) {
	secret := errors.New("bad key octs_live_SECRET")
	cases := map[error]string{
		nil:                                   "no_sensor",
		errSensorPaused:                       "paused",
		fmt.Errorf("wrap: %w", errBearerOnV3): "bearer_on_v3",
		secret:                                "invalid_credentials",
	}
	for err, want := range cases {
		if got := sensorAuthFailureReason(err); got != want {
			t.Errorf("sensorAuthFailureReason(%v) = %q, want %q", err, got, want)
		}
	}
}
