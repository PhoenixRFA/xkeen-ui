package xkeen

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateSubCurl(t *testing.T) {
	out, err := ValidateSubCurl("url = \"https://x\"\r\nheader = \"x-hwid: 1\"")
	if err != nil || out != "url = \"https://x\"\nheader = \"x-hwid: 1\"\n" {
		t.Fatalf("%q %v", out, err)
	}
	for _, bad := range []string{"", "   \n", "header = \"a\"\n", "user-agent = x\n"} {
		if _, err := ValidateSubCurl(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestBackupPrune(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sub.curl")
	os.WriteFile(src, []byte("url = x\n"), 0o600)
	bk := filepath.Join(dir, "backup")
	for i := 0; i < 4; i++ {
		if _, err := Backup(src, bk, "sub.curl.", 2); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	list, _ := ListBackups(bk, "sub.curl.")
	if len(list) != 2 {
		t.Fatalf("want 2 backups, got %d", len(list))
	}
	if !ValidBackupName(list[0].Name, "sub.curl.") || ValidBackupName("../etc/passwd", "sub.curl.") {
		t.Fatal("name validation")
	}
}
