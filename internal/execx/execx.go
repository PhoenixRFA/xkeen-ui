// Package execx runs only whitelisted commands: no shell, timeout, capped output.
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

const safePath = "PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin"

type Runner struct{ allowed map[string]bool }

func New(allowed ...string) *Runner {
	r := &Runner{allowed: map[string]bool{}}
	for _, a := range allowed {
		r.allowed[a] = true
	}
	return r
}

type Result struct {
	Output string
	Code   int
}

type capBuf struct {
	buf bytes.Buffer
	max int
}

func (c *capBuf) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// Run executes name (must be whitelisted, absolute path or bare name) with args.
// A non-zero exit code is returned in Result.Code, not as an error.
func (r *Runner) Run(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) (Result, error) {
	if !r.allowed[name] {
		return Result{Code: -1}, fmt.Errorf("command not allowed: %s", name)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolve(name), args...)
	cmd.Env = append(append(os.Environ(), safePath), env...)
	out := &capBuf{max: 1 << 20}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 2 * time.Second // init scripts leave daemons holding the pipe open
	err := cmd.Run()
	res := Result{Output: ansiRe.ReplaceAllString(out.buf.String(), "")} // drop terminal colors
	if errors.Is(err, exec.ErrWaitDelay) {
		return res, nil // process exited with 0; a background child kept the pipe
	}
	if ctx.Err() != nil {
		res.Code = -1
		return res, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.Code = ee.ExitCode()
		return res, nil
	}
	if err != nil {
		res.Code = -1
	}
	return res, err
}

// resolve finds a bare command name in the fixed safe PATH (init.d may run with a tiny PATH).
func resolve(name string) string {
	if strings.Contains(name, "/") {
		return name
	}
	for _, d := range strings.Split(strings.TrimPrefix(safePath, "PATH="), ":") {
		p := d + "/" + name
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return name
}

// Proc is a long-running whitelisted process (the temporary xray of the tunnel check).
type Proc struct {
	cmd  *exec.Cmd
	out  *capBuf
	done chan struct{}
}

func (r *Runner) Start(env []string, name string, args ...string) (*Proc, error) {
	if !r.allowed[name] {
		return nil, fmt.Errorf("command not allowed: %s", name)
	}
	cmd := exec.Command(resolve(name), args...)
	cmd.Env = append(append(os.Environ(), safePath), env...)
	out := &capBuf{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &Proc{cmd: cmd, out: out, done: make(chan struct{})}
	go func() { cmd.Wait(); close(p.done) }()
	return p, nil
}

func (p *Proc) Done() <-chan struct{} { return p.done }

// Stop kills the process and returns what it printed.
func (p *Proc) Stop() string {
	p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
	}
	return ansiRe.ReplaceAllString(p.out.buf.String(), "")
}
