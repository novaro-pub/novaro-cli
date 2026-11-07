package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"novaro-cli/internal/api"
	"novaro-cli/internal/config"
)

// pollEvery is how often login asks whether the browser confirmed.
var pollEvery = 2 * time.Second

type pairing struct {
	ID         string      `json:"id"`
	Code       string      `json:"code"`
	PollSecret string      `json:"poll_secret"`
	URL        string      `json:"url"`
	ExpiresAt  unixSeconds `json:"expires_at"`
	DeviceName string      `json:"device_name"`
}

// unixSeconds is a time in seconds since the Unix epoch, as the pairing
// API answers it: the API writes its int64s as JSON strings ("1762531200"),
// as protojson does; a JSON number is taken as well.
type unixSeconds int64

func (u *unixSeconds) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*u = 0
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("a time in seconds since the epoch: %q", b)
	}
	*u = unixSeconds(n)
	return nil
}

type pairingPoll struct {
	Status       string      `json:"status"`
	APIKey       string      `json:"api_key"`
	KeyPrefix    string      `json:"key_prefix"`
	KeyExpiresAt unixSeconds `json:"key_expires_at"`
}

func (a *app) loginCmd() *cobra.Command {
	var market, device string
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Pair novaro with your account in the browser",
		Long: `login opens the merchant portal's "Allow CLI access" page. Once an admin or
a developer of the account confirms it there, novaro gets a CLI key
(rk_test_…): test mode only, for 90 days. The key is kept in the OS
keychain, or, on a machine with none, in novaro's config file, readable by
you alone (login says which).

With --api-key, login keeps that key instead and opens no browser: for CI.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The flag, not $NOVARO_API_KEY: an exported key is for the
			// other commands, and login pairs in the browser.
			if cmd.Flags().Changed("api-key") {
				return a.saveKey(device)
			}
			return a.pair(cmd.Context(), market, device, noBrowser)
		},
	}
	f := cmd.Flags()
	f.StringVar(&market, "market", "in", "the market of the account (its key's market)")
	f.StringVar(&device, "device-name", "", "the name the portal shows for this machine (default: its host name)")
	f.BoolVar(&noBrowser, "no-browser", false, "print the link instead of opening it")
	return cmd
}

// saveKey keeps --api-key as login's key.
func (a *app) saveKey(device string) error {
	mode, keyMarket, ok := keyParts(a.apiKey)
	if !ok {
		return errors.New("--api-key is not an API key: it starts sk_test_, sk_live_ or rk_test_")
	}
	if mode == "live" {
		return errors.New("login keeps test keys only; pass a live key to each command with --api-key instead")
	}
	base := a.base(config.Profile{})
	if err := checkBase(base); err != nil {
		return err
	}
	p := config.Profile{APIBase: base, Market: keyMarket, KeyPrefix: prefixOf(a.apiKey), DeviceName: device}
	if p.DeviceName == "" {
		p.DeviceName = hostDevice()
	} else {
		p.DeviceName = truncate(p.DeviceName, 64)
	}
	return a.save(p, a.apiKey)
}

func (a *app) save(p config.Profile, key string) error {
	store, err := a.loadStore()
	if err != nil {
		return err
	}
	inFile, err := store.Save(p, key)
	if err != nil {
		return err
	}
	where := "the OS keychain"
	if inFile {
		where = store.Path + ", readable by you alone (no OS keychain answered)"
	}
	fmt.Fprintf(a.out, "Done. The key %s… is kept in %s.\n", p.KeyPrefix, where)
	return nil
}

// pair runs the browser pairing: start, show the code, poll until the
// portal confirms it or it expires.
func (a *app) pair(ctx context.Context, market, device string, noBrowser bool) error {
	market = strings.ToLower(strings.TrimSpace(market))
	if device == "" {
		device = hostDevice()
	}
	device = truncate(device, 64)
	if _, err := a.loadStore(); err != nil {
		return err
	}
	base := a.base(config.Profile{})
	if err := checkBase(base); err != nil {
		return err
	}
	c := &api.Client{Base: base, UserAgent: a.userAgent(), HTTPClient: a.httpClient}
	var pr pairing
	if err := c.Do(ctx, http.MethodPost, "/cli/pairings/"+url.PathEscape(market), nil, nil,
		map[string]string{"device_name": device}, &pr); err != nil {
		return fmt.Errorf("start pairing: %w", err)
	}
	fmt.Fprintf(a.out, "Your pairing code is: %s\n", pr.Code)
	fmt.Fprintln(a.out, "It confirms you are pairing this machine. Check that the portal shows the same code.")
	if noBrowser || !safeLink(pr.URL) || openBrowser(ctx, pr.URL) != nil {
		fmt.Fprintf(a.out, "Open this link to allow access: %s\n", pr.URL)
	} else {
		fmt.Fprintf(a.out, "Opened %s in your browser.\n", pr.URL)
	}
	fmt.Fprintln(a.out, "Waiting for confirmation…")

	// The pairing lives 10 minutes, after which a poll is 404: the server
	// says when it ended. The deadline here only stops a poll that never
	// gets an answer, on this machine's clock, which may differ.
	deadline := a.now().Add(11 * time.Minute)
	path := "/cli/pairings/" + url.PathEscape(market) + "/" + url.PathEscape(pr.ID) + "/poll"
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		var poll pairingPoll
		err := c.Do(ctx, http.MethodPost, path, nil, nil, map[string]string{"poll_secret": pr.PollSecret}, &poll)
		var apiErr *api.Error
		switch {
		case errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound:
			return errors.New("the pairing ended before it was confirmed: run novaro login again")
		case err != nil:
			// Polled too often (429) or the network: the next poll may
			// pass, until the pairing ends.
			if a.now().After(deadline) {
				return fmt.Errorf("confirm pairing: %w", err)
			}
			continue
		}
		if poll.Status == "confirmed" && poll.APIKey != "" {
			// The prefix as novaro reads it from a key, which listen
			// matches its kept secret by.
			p := config.Profile{APIBase: base, Market: market, DeviceName: device, KeyPrefix: prefixOf(poll.APIKey), KeyExpiresAt: int64(poll.KeyExpiresAt)}
			if err := a.save(p, poll.APIKey); err != nil {
				return err
			}
			if p.KeyExpiresAt != 0 {
				fmt.Fprintf(a.out, "It works in test mode until %s.\n", time.Unix(p.KeyExpiresAt, 0).Format(time.DateOnly))
			}
			return nil
		}
		if a.now().After(deadline) {
			return errors.New("the pairing expired before it was confirmed: run novaro login again")
		}
	}
}

func (a *app) logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Forget login's key on this machine",
		Long: `logout removes the key from the OS keychain and the config file. The key
itself stays valid until it expires or is expired in the portal
(Developers › API keys › CLI keys).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := a.loadStore()
			if err != nil {
				return err
			}
			if err := store.Clear(); err != nil {
				return err
			}
			fmt.Fprintln(a.out, "Logged out. Expire the key in the portal to stop it working anywhere.")
			return nil
		},
	}
}

// prefixOf is the part of a key the portal shows: kind, mode, market and
// 8 characters of the secret.
func prefixOf(key string) string {
	i := strings.LastIndexByte(key, '_')
	if i < 0 || len(key) < i+1+8 {
		return ""
	}
	return key[:i+1+8]
}

// hostDevice is this machine's name, as a device.
func hostDevice() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		h = "novaro"
	}
	return truncate(h, 64)
}

func truncate(s string, n int) string {
	for utf8.RuneCountInString(s) > n {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// safeLink says whether login may open u: the portal's page over https, or
// over http on this machine as a local stack has it; never a file, a path
// or another program's scheme a server could name.
func safeLink(u string) bool {
	l, err := url.Parse(u)
	if err != nil || l.Host == "" {
		return false
	}
	switch l.Scheme {
	case "https":
		return true
	case "http":
		return loopback(l.Hostname())
	}
	return false
}

// openBrowser opens u in the default browser.
func openBrowser(ctx context.Context, u string) error {
	if u == "" {
		return errors.New("no link")
	}
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.CommandContext(ctx, "open", u)
	case "windows":
		c = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", u)
	default:
		c = exec.CommandContext(ctx, "xdg-open", u)
	}
	return c.Start()
}
