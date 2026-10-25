// Package auth: PBKDF2 password hashing, in-memory sessions, login rate limit.
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"

	"xkeen-ui/internal/config"
)

func derive(pw string, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, pw, salt, iter, 32)
}

// Hash returns base64 salt and hash for a new password.
func Hash(pw string, iter int) (salt, hash string, err error) {
	s := make([]byte, 16)
	if _, err = rand.Read(s); err != nil {
		return
	}
	h, err := derive(pw, s, iter)
	if err != nil {
		return
	}
	return base64.StdEncoding.EncodeToString(s), base64.StdEncoding.EncodeToString(h), nil
}

// Verify compares in constant time; the hash is computed even for a wrong user.
func Verify(a config.Auth, user, pw string) bool {
	salt, err1 := base64.StdEncoding.DecodeString(a.Salt)
	want, err2 := base64.StdEncoding.DecodeString(a.Hash)
	if err1 != nil || err2 != nil || a.Iterations <= 0 {
		return false
	}
	got, err := derive(pw, salt, a.Iterations)
	if err != nil {
		return false
	}
	okPw := subtle.ConstantTimeCompare(got, want) == 1
	okUser := subtle.ConstantTimeCompare([]byte(user), []byte(a.User)) == 1
	return okPw && okUser
}

type Sessions struct {
	mu  sync.Mutex
	m   map[string]time.Time
	ttl time.Duration
}

func NewSessions(ttl time.Duration) *Sessions {
	return &Sessions{m: map[string]time.Time{}, ttl: ttl}
}

func (s *Sessions) New() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	t := hex.EncodeToString(b)
	s.mu.Lock()
	s.m[t] = time.Now().Add(s.ttl)
	s.mu.Unlock()
	return t, nil
}

func (s *Sessions) Valid(t string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[t]
	if ok && time.Now().After(exp) {
		delete(s.m, t)
		return false
	}
	return ok
}

func (s *Sessions) Delete(t string) { s.mu.Lock(); delete(s.m, t); s.mu.Unlock() }

// Limiter blocks an IP for 5 minutes after 5 failed logins.
type Limiter struct {
	mu sync.Mutex
	m  map[string]*entry
}
type entry struct {
	n     int
	until time.Time
}

func NewLimiter() *Limiter { return &Limiter{m: map[string]*entry{}} }

func (l *Limiter) Blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[ip]
	return e != nil && time.Now().Before(e.until)
}

func (l *Limiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[ip]
	if e == nil {
		e = &entry{}
		l.m[ip] = e
	}
	if e.n++; e.n >= 5 {
		e.n, e.until = 0, time.Now().Add(5*time.Minute)
	}
}

func (l *Limiter) Reset(ip string) { l.mu.Lock(); delete(l.m, ip); l.mu.Unlock() }
