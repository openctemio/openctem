package extensionhost

import "fmt"

// removedSettings are the settings of features that left the core in an
// earlier release and are now provided by an extension. A server whose build
// has no extension declaring such a setting refuses to start while it is set:
// the operator asked for a feature this build does not have and must never
// lose it unnoticed (for example an off-box copy of the administrators'
// audit log). A setting removed from the core never comes back with another
// meaning.
var removedSettings = []string{
	// The off-box administrators' audit stream.
	"ADMIN_AUDIT_SINK",
	"ADMIN_AUDIT_SINK_SECRET",
	"ADMIN_AUDIT_SINK_SYSLOG_CA_FILE",
	"ADMIN_AUDIT_SINK_SYSLOG_CLIENT_CERT",
	"ADMIN_AUDIT_SINK_SYSLOG_CLIENT_KEY",
	"ADMIN_AUDIT_SINK_HEAD_INTERVAL",
}

// CheckRemovedSettings returns an error naming the first removed setting
// that is set while no extension of the build declares it. The value is
// never repeated.
func (s *Set) CheckRemovedSettings(getenv func(string) string) error {
	for _, k := range removedSettings {
		if getenv(k) != "" && !s.Declares(k) {
			return fmt.Errorf("%s is set, but its feature is provided by an extension in this release and this build has none that declares it: unset it, or run a build that includes it", k)
		}
	}
	return nil
}
