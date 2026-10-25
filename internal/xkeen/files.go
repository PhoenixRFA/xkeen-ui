package xkeen

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var subURLRe = regexp.MustCompile(`(?m)^\s*(--)?url\s*[=: ]`)

// ValidateSubCurl normalizes line endings and checks the basics of a curl config file.
func ValidateSubCurl(s string) (string, error) {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	switch {
	case strings.TrimSpace(s) == "":
		return "", fmt.Errorf("file is empty")
	case len(s) > 16<<10:
		return "", fmt.Errorf("file is too large (max 16 KB)")
	case !utf8.ValidString(s) || strings.ContainsRune(s, 0):
		return "", fmt.Errorf("file must be valid UTF-8 text")
	case !subURLRe.MatchString(s):
		return "", fmt.Errorf(`no "url = ..." line found`)
	}
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s, nil
}

// WriteAtomic writes through a temp file in the same directory and renames it into place.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

type BackupInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

func backupRe(prefix string) *regexp.Regexp {
	return regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `\d{8}-\d{6}\.\d{3}$`)
}

// ValidBackupName guards against path tricks: only names this package would create.
func ValidBackupName(name, prefix string) bool { return backupRe(prefix).MatchString(name) }

// ListBackups returns backups newest first.
func ListBackups(dir, prefix string) ([]BackupInfo, error) {
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	re := backupRe(prefix)
	var out []BackupInfo
	for _, e := range ents {
		if e.IsDir() || !re.MatchString(e.Name()) {
			continue
		}
		if fi, err := e.Info(); err == nil {
			out = append(out, BackupInfo{Name: e.Name(), Size: fi.Size(), ModTime: fi.ModTime().UTC().Format(time.RFC3339)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// Backup copies src into dir as prefix+timestamp (mode 0600) and keeps only the newest `keep`.
// It returns "" if src does not exist yet.
func Backup(src, dir, prefix string, keep int) (string, error) {
	b, err := os.ReadFile(src)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := prefix + time.Now().Format("20060102-150405.000")
	if err := WriteAtomic(filepath.Join(dir, name), b, 0o600); err != nil {
		return "", err
	}
	if all, err := ListBackups(dir, prefix); err == nil && keep > 0 && len(all) > keep {
		for _, old := range all[keep:] {
			os.Remove(filepath.Join(dir, old.Name))
		}
	}
	return name, nil
}
