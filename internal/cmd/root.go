// Package cmd is novaro's commands.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"novaro-cli/internal/api"
	"novaro-cli/internal/config"
)

// Build is what goreleaser stamps into the binary.
type Build struct {
	Version, Commit, Date string
}

// DefaultAPIBase is the API's address when neither --api-base,
// NOVARO_API_BASE nor login's profile names one. A release sets it with
// -ldflags; a build of its own talks to the local stack's edge.
var DefaultAPIBase = "http://localhost:28081"

// app is what every command shares.
type app struct {
	build  Build
	out    io.Writer
	errOut io.Writer
	store  *config.Store
	// storeErr is why there is no store: no config directory. Only the
	// commands that read or write it fail on it.
	storeErr error
	now      func() time.Time
	// httpClient is the API's; tests replace it.
	httpClient *http.Client

	apiKey  string
	apiBase string
}

// Execute runs novaro with the process's arguments and returns its exit
// code.
func Execute(b Build) int {
	// The first SIGINT or SIGTERM ends the command's context, and the
	// command winds down; a second one, the process, at once.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	var first atomic.Value
	go func() {
		sig := <-signals
		first.Store(sig)
		cancel()
		<-signals
		os.Exit(exitCode(sig))
	}()
	store, storeErr := config.Default()
	a := &app{build: b, out: os.Stdout, errOut: os.Stderr, store: store, storeErr: storeErr, now: time.Now}
	root := a.root()
	root.SetArgs(os.Args[1:])
	if err := root.ExecuteContext(ctx); err != nil {
		if sig, ok := first.Load().(os.Signal); ok && errors.Is(err, context.Canceled) {
			return exitCode(sig)
		}
		fmt.Fprintln(os.Stderr, "novaro:", err)
		return 1
	}
	return 0
}

// exitCode is a shell's for a process the signal ended: 128 + its number.
func exitCode(sig os.Signal) int {
	if sig == syscall.SIGTERM {
		return 143
	}
	return 130
}

func (a *app) root() *cobra.Command {
	root := &cobra.Command{
		Use:   "novaro",
		Short: "The NovaroPay command-line tool",
		Long: `novaro forwards your account's test-mode webhook events to a server on
your machine, triggers test payments and reads or resends events.

Start with: novaro login`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       a.build.Version,
	}
	root.SetOut(a.out)
	root.SetErr(a.errOut)
	root.SetVersionTemplate("novaro version {{.Version}}\n")
	pf := root.PersistentFlags()
	// $NOVARO_API_KEY is read when the command runs, not as the flag's
	// default: --help prints defaults.
	pf.StringVar(&a.apiKey, "api-key", "", "use this key instead of login's (sk_test_…, sk_live_… or rk_test_…; or $NOVARO_API_KEY)")
	root.PersistentPreRun = func(cmd *cobra.Command, _ []string) {
		if a.apiKey == "" && !cmd.Flags().Changed("api-key") {
			a.apiKey = os.Getenv("NOVARO_API_KEY")
		}
	}
	pf.StringVar(&a.apiBase, "api-base", "", "the API's address (default: login's, or $NOVARO_API_BASE)")
	root.AddCommand(a.loginCmd(), a.logoutCmd(), a.listenCmd(), a.triggerCmd(), a.eventsCmd(), a.versionCmd())
	return root
}

// keyRE is the shape of an API key: kind, mode, market, secret.
var keyRE = regexp.MustCompile(`^(sk|rk)_(live|test)_([a-z][a-z0-9]{1,7})_[0-9A-Za-z]+$`)

// keyParts splits a key into its mode and market; ok is false for a key of
// another shape.
func keyParts(key string) (mode, market string, ok bool) {
	m := keyRE.FindStringSubmatch(key)
	if m == nil {
		return "", "", false
	}
	return m[2], m[3], true
}

// base is the API's address: --api-base, $NOVARO_API_BASE, the profile's,
// the build's.
func (a *app) base(p config.Profile) string {
	for _, b := range []string{a.apiBase, os.Getenv("NOVARO_API_BASE"), p.APIBase, DefaultAPIBase} {
		if b != "" {
			return strings.TrimRight(b, "/")
		}
	}
	return ""
}

// checkBase refuses an address a key must not be sent to: one that is not
// http(s), or plain http to anything but this machine.
func checkBase(base string) error {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return fmt.Errorf("the API's address %q is not a URL", base)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if loopback(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("the API's address %q is plain http: only https, or http to this machine", base)
	}
	return fmt.Errorf("the API's address %q is not http(s)", base)
}

func loopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// loadStore is the store, or why there is none.
func (a *app) loadStore() (*config.Store, error) {
	if a.storeErr != nil {
		return nil, a.storeErr
	}
	return a.store, nil
}

// client is the API client with the key a command uses: --api-key, or
// login's. live says whether the command may use a live key. Login's key
// goes to login's address only: another --api-base or $NOVARO_API_BASE
// needs a key of its own.
func (a *app) client(live bool) (*api.Client, error) {
	key := a.apiKey
	var p config.Profile
	base := ""
	if key == "" {
		store, err := a.loadStore()
		if err != nil {
			return nil, err
		}
		if p, key, err = store.Load(); err != nil {
			return nil, err
		}
		if p.Expired(a.now()) {
			return nil, fmt.Errorf("the key %s… expired on %s: run novaro login again", p.KeyPrefix, time.Unix(p.KeyExpiresAt, 0).Format(time.DateOnly))
		}
		base = a.base(p)
		if p.APIBase != "" && base != strings.TrimRight(p.APIBase, "/") {
			return nil, fmt.Errorf("login's key is for %s, not %s: pass --api-key for it, or run novaro login against it", p.APIBase, base)
		}
	} else {
		mode, _, ok := keyParts(key)
		if !ok {
			return nil, errors.New("--api-key is not an API key: it starts sk_test_, sk_live_ or rk_test_")
		}
		if mode == "live" && !live {
			return nil, errors.New("this command works in test mode only: pass a test key (sk_test_… or rk_test_…)")
		}
		base = a.base(config.Profile{})
	}
	if err := checkBase(base); err != nil {
		return nil, err
	}
	return &api.Client{
		Base:       base,
		Key:        key,
		UserAgent:  a.userAgent(),
		HTTPClient: a.httpClient,
	}, nil
}

func (a *app) userAgent() string {
	return "novaro/" + a.build.Version
}

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print novaro's version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(a.out, "novaro version %s (commit %s, built %s)\n", a.build.Version, a.build.Commit, a.build.Date)
			return err
		},
	}
}
