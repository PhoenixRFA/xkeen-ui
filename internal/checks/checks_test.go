package checks

import "testing"

func TestParsePing(t *testing.T) {
	out := "3 packets transmitted, 3 packets received, 0% packet loss\nround-trip min/avg/max = 35.191/35.273/35.340 ms\n"
	p := ParsePing(out)
	if p.Sent != 3 || p.Recv != 3 || p.LossPct != 0 || p.AvgMs != 35.273 {
		t.Fatalf("%+v", p)
	}
}

func TestParseNslookup(t *testing.T) {
	out := "Server:    192.168.1.1\nAddress 1: 192.168.1.1\n\nName:      ya.ru\nAddress 1: 77.88.44.242 ya.ru\nAddress 2: 5.255.255.242 ya.ru\nAddress 4: 2a02:6b8::2:242 ya.ru\n"
	if ip, ok := ParseNslookup(out); !ok || ip != "77.88.44.242" {
		t.Fatalf("%q %v", ip, ok)
	}
	if _, ok := ParseNslookup("nslookup: can't resolve 'x.invalid': Temporary failure in name resolution\n"); ok {
		t.Fatal("must not resolve")
	}
}

func TestCleanDomain(t *testing.T) {
	if d, err := CleanDomain(" HTTPS://Ya.RU/path?x=1 "); err != nil || d != "ya.ru" {
		t.Fatalf("%q %v", d, err)
	}
	for _, bad := range []string{"", "localhost", "a b.com", "яндекс.рф", "-a.com", "a.com;ls"} {
		if _, err := CleanDomain(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}
