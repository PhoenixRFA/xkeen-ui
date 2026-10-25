package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"xkeen-ui/internal/api"
	"xkeen-ui/internal/auth"
	"xkeen-ui/internal/config"
)

var version = "dev" // set with -ldflags "-X main.version=..."

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "passwd":
			os.Exit(cmdPasswd(args[1:]))
		case "init":
			os.Exit(cmdInit(args[1:]))
		case "version":
			fmt.Println("xkeen-ui " + version)
			return
		}
	}
	fs := flag.NewFlagSet("xkeen-ui", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "config file")
	v := fs.Bool("v", false, "print version")
	vv := fs.Bool("version", false, "print version")
	fs.Parse(args)
	if *v || *vv {
		fmt.Println("xkeen-ui " + version)
		return
	}
	os.Exit(serve(*cfgPath))
}

func serve(cfgPath string) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Printf("config: %v", err)
		return 1
	}
	if cfg.Auth.Hash == "" {
		log.Print("no password set: run `xkeen-ui init` or `xkeen-ui passwd`")
		return 1
	}
	srv, err := api.New(cfgPath, cfg, version)
	if err != nil {
		log.Printf("init: %v", err)
		return 1
	}
	hs := &http.Server{Addr: cfg.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(ctx)
	}()
	log.Printf("xkeen-ui %s listening on %s", version, cfg.Listen)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("server: %v", err)
		return 1
	}
	return 0
}

const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func randomPassword(n int) string {
	b := make([]byte, n)
	for i := range b {
		x, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[x.Int64()]
	}
	return string(b)
}

func readLine(r *bufio.Reader, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	stty := func(a string) { c := exec.Command("stty", a); c.Stdin = os.Stdin; c.Run() }
	stty("-echo")
	defer stty("echo")
	line, err := r.ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func setPassword(cfg *config.Config, pw string) error {
	if len(pw) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if cfg.Auth.Iterations <= 0 {
		cfg.Auth.Iterations = 200000
	}
	salt, hash, err := auth.Hash(pw, cfg.Auth.Iterations)
	if err != nil {
		return err
	}
	cfg.Auth.Salt, cfg.Auth.Hash = salt, hash
	return nil
}

// xkeen-ui passwd [-config F] [-random]
func cmdPasswd(args []string) int {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "config file")
	random := fs.Bool("random", false, "generate a random password")
	fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	pw := ""
	if *random {
		pw = randomPassword(14)
	} else {
		r := bufio.NewReader(os.Stdin)
		a, err := readLine(r, "New password: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		b, _ := readLine(r, "Repeat: ")
		if a != b {
			fmt.Fprintln(os.Stderr, "passwords do not match")
			return 1
		}
		pw = a
	}
	if err := setPassword(cfg, pw); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := cfg.Save(*cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *random {
		fmt.Printf("User: %s\nPassword: %s\n", cfg.Auth.User, pw)
	}
	fmt.Println("Password updated. Restart the service to drop active sessions:")
	fmt.Println("  /opt/etc/init.d/S99xkeen-ui restart")
	return 0
}

// xkeen-ui init [-config F] [-listen IP:PORT]: create config with a random password (used by the installer).
func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "config file")
	listen := fs.String("listen", "", "listen address, default from config defaults")
	allow := fs.String("allow", "", "comma-separated CIDRs allowed to connect")
	dns := fs.String("dns", "", "DNS server used by checks")
	fs.Parse(args)
	if _, err := os.Stat(*cfgPath); err == nil {
		fmt.Fprintln(os.Stderr, "config already exists, not overwriting:", *cfgPath)
		return 1
	}
	cfg := config.Default()
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *allow != "" {
		cfg.AllowCIDRs = strings.Split(*allow, ",")
	}
	if *dns != "" {
		cfg.DNSServer = *dns
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	pw := randomPassword(14)
	if err := setPassword(cfg, pw); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := cfg.Save(*cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("Config: %s\nListen: %s\nUser: %s\nPassword: %s\n", *cfgPath, cfg.Listen, cfg.Auth.User, pw)
	return 0
}
