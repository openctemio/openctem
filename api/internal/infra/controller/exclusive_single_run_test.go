package controller

import "testing"

// Controllers whose reconcile has external side effects (tracker pushes,
// emails, remote syncs, audit rows) must hold the controller lease so several
// API replicas never run them at once.
func TestSingleRunControllersAreExclusive(t *testing.T) {
	for _, c := range []Controller{
		&TaskTicketController{},
		&DefectDojoSyncController{},
		&SCMSyncController{},
		&SAMLCertExpiryController{},
		&ScopePendingController{},
	} {
		ex, ok := c.(Exclusive)
		if !ok || !ex.Exclusive() {
			t.Errorf("%s must be Exclusive", c.Name())
		}
	}
}
