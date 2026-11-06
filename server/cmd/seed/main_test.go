package main

import "testing"

func TestConfirmClean(t *testing.T) {
	cases := []struct {
		clean, yes bool
		wantErr    bool
	}{
		{false, false, false},
		{false, true, false},
		{true, false, true},
		{true, true, false},
	}
	for _, c := range cases {
		if err := confirmClean(c.clean, c.yes); (err != nil) != c.wantErr {
			t.Errorf("confirmClean(%v,%v) = %v, wantErr %v", c.clean, c.yes, err, c.wantErr)
		}
	}
}
