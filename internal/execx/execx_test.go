package execx

import "testing"

func TestAnsiStrip(t *testing.T) {
	in := "\x1b[93mxray\x1b[0m \x1b[92mrunning\x1b[0m"
	if got := ansiRe.ReplaceAllString(in, ""); got != "xray running" {
		t.Fatalf("got %q", got)
	}
}
