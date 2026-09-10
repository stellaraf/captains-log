package main

import "testing"

func TestFIPSRequirementFailsClosed(t *testing.T) {
	cases := []struct {
		setting   string
		enabled   bool
		wantError bool
	}{{"true", false, true}, {"true", true, false}, {"false", false, false}, {"false", true, false}, {"invalid", true, true}, {"", false, true}}
	for _, tc := range cases {
		if err := requireFIPSMode(tc.setting, tc.enabled); (err != nil) != tc.wantError {
			t.Errorf("setting %q enabled=%v: %v", tc.setting, tc.enabled, err)
		}
	}
}
