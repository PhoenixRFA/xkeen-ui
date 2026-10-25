package policy

import "testing"

func TestParse(t *testing.T) {
	pol, err := ParsePolicies([]byte(`{"Policy10":{"description":"x"},"Policy1":{"description":"xkeen"},"Policy0":{"description":"VPN"},"junk":{}}`), []string{"xkeen"})
	if err != nil || len(pol) != 3 || pol[0].ID != "Policy0" || pol[2].ID != "Policy10" || !pol[1].Highlight {
		t.Fatalf("%v %+v", err, pol)
	}
	cl, err := ParseHosts([]byte(`{"host":[{"mac":"AA:BB:CC:DD:EE:FF","ip":"192.168.1.5","name":"","hostname":"phone","policy":"Policy1","active":true},{"mac":"bad"}]}`))
	if err != nil || len(cl) != 1 || cl[0].Name != "phone" || cl[0].MAC != "aa:bb:cc:dd:ee:ff" || !cl[0].Online {
		t.Fatalf("%v %+v", err, cl)
	}
}

func TestSetCommand(t *testing.T) {
	if SetCommand("aa:bb:cc:dd:ee:ff", "") != "no ip hotspot host aa:bb:cc:dd:ee:ff policy" {
		t.Fatal("remove")
	}
	if SetCommand("aa:bb:cc:dd:ee:ff", "Policy1") != "ip hotspot host aa:bb:cc:dd:ee:ff policy Policy1" {
		t.Fatal("set")
	}
}
