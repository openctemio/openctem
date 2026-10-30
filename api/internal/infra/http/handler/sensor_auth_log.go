package handler

import "errors"

// sensorAuthFailureReason names why a sensor request failed authentication,
// for the debug log. It never returns the error text: errors from the
// credential checks can carry material from the request headers.
func sensorAuthFailureReason(err error) string {
	switch {
	case err == nil:
		return "no_sensor"
	case errors.Is(err, errSensorPaused):
		return "paused"
	case errors.Is(err, errBearerOnV3):
		return "bearer_on_v3"
	default:
		return "invalid_credentials"
	}
}
