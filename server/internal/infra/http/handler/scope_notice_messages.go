package handler

import notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"

// exclusionReducedMessage is the language-neutral notice that an exclusion
// in effect was shortened, removed or deactivated (scope.exclusion_<action>).
func exclusionReducedMessage(action, kind, pattern string) *notificationdom.Message {
	return notificationdom.Msg("scope.exclusion_"+action, "type", kind, "pattern", pattern)
}

// t2DurationMessage is the notice that the longest intrusive entry changed;
// "permanent" is a nested message, the other values (7d, 30d, 90d, 365d) are
// language-neutral and sent as they are.
func t2DurationMessage(duration, reason string) *notificationdom.Message {
	var d any = duration
	if duration == "permanent" {
		d = notificationdom.Msg("scope.t2_duration.permanent")
	}
	return notificationdom.Msg("scope.t2_duration_changed", "duration", d, "reason", reason)
}
