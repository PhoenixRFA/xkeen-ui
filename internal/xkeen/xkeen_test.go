package xkeen

import (
	"os"
	"path/filepath"
	"testing"
)

var remarks = []string{"🌏 Автовыбор", "🇩🇪 [DE] Германия ⚡️", "🇩🇪 [DE] Германия 2", "🇳🇱 [NL] - Нидерланды"}

func TestEvaluate(t *testing.T) {
	parts, eff := Evaluate("Германия|Нидерланды", remarks)
	if parts[0].OK || parts[0].Matches != 2 {
		t.Fatalf("Германия must match 2 nodes: %+v", parts[0])
	}
	if eff != "🇳🇱 [NL] - Нидерланды" {
		t.Fatalf("effective = %q", eff)
	}
	if _, eff := Evaluate("Нет такого", remarks); eff != "" {
		t.Fatalf("expected no effective node, got %q", eff)
	}
}

func TestValidateMain(t *testing.T) {
	for _, bad := range []string{"", `a"b`, "a$b", "a|", "|a", "a\nb", `a\b`} {
		if ValidateMain(bad) == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	if err := ValidateMain("Нидерланды|Германия ⚡️"); err != nil {
		t.Errorf("valid value rejected: %v", err)
	}
}

func TestLastSubAttempt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub.log")
	data := "2026-10-25 13:17:01 no changes (17 entries)\n2026-10-25 13:17:01 gen: main-vpn <- \"x\"\ncurl: (6) oops\n"
	os.WriteFile(p, []byte(data), 0o600)
	st, msg := LastSubAttempt(p)
	if st != "2026-10-25 13:17:01" || msg != "no changes (17 entries)" {
		t.Fatalf("got %q %q", st, msg)
	}
}

func TestMaskJSON(t *testing.T) {
	b, err := MaskJSON([]byte(`{"settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"secret"}]}]},"tag":"main-vpn"}`))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if contains(s, "1.2.3.4") || contains(s, "secret") || !contains(s, "main-vpn") {
		t.Fatalf("bad mask: %s", s)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
