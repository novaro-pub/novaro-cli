package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"novaro-cli/internal/config"
	"novaro-cli/internal/listen"
)

func (a *app) listenCmd() *cobra.Command {
	var forwardTo, apiVersion, headers, format, device string
	var events []string
	var latest, skipVerify, printSecret bool
	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Forward test-mode webhook events to a server on your machine",
		Long: `listen receives your account's test-mode events as webhooks, signed as
your endpoints' are, and POSTs each to --forward-to. Your server's answer
goes back as the delivery's attempt: the portal shows it under the
machine's "Local listener".

The signing secret (whsec_…) is this machine's, for this key, and stays the
same across restarts; verify PSP-Signature with it as you would an
endpoint's.

  novaro listen --forward-to localhost:3000/webhooks
  novaro listen --events payment.succeeded,payment.failed --forward-to localhost:3000/webhooks`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if latest && apiVersion != "" {
				return errors.New("pass --api-version or --latest, not both")
			}
			if format != "" && format != "json" {
				return fmt.Errorf("--format %q: the only format is json", format)
			}
			c, err := a.client(false)
			if err != nil {
				return err
			}
			if mode, _, _ := keyParts(c.Key); mode == "live" {
				return errors.New("listen works in test mode only")
			}
			wsURL, err := listen.SocketURL(c.Base)
			if err != nil {
				return err
			}
			fwd, err := forwardURL(forwardTo)
			if err != nil {
				return err
			}
			h, err := parseHeaders(headers)
			if err != nil {
				return err
			}
			if latest {
				apiVersion = "latest"
			}
			// Login's key is the one whose last secret the profile keeps;
			// a CLI key names its own device, a secret key this machine:
			// the name login kept, so a host name that changes with the
			// network does not make a new device with a new secret.
			fromLogin := a.apiKey == ""
			var profile config.Profile
			if store, err := a.loadStore(); err == nil && fromLogin {
				profile, _ = store.Profile()
			}
			if strings.HasPrefix(c.Key, "rk_") {
				device = ""
			} else if device == "" {
				device = profile.DeviceName
				if h, err := os.Hostname(); device == "" && err == nil {
					device = truncate(h, 64)
				}
			}
			prefix := prefixOf(c.Key)
			if printSecret && fromLogin {
				// A listen opened only to read the secret would replace
				// the session of a listen running with the same key and
				// device.
				if secret := profile.ListenSecretFor(prefix, device); secret != "" {
					fmt.Fprintln(a.out, secret)
					return nil
				}
			}
			cfg := listen.Config{
				URL: wsURL, Key: c.Key, UserAgent: a.userAgent(),
				Events: splitList(events), APIVersion: apiVersion, DeviceName: device,
				ForwardTo: fwd, Headers: h, SkipVerify: skipVerify, Once: printSecret,
			}
			keep := func(secret string) {
				if !fromLogin {
					return
				}
				if store, err := a.loadStore(); err == nil {
					_ = store.SetListenSecret(prefix, device, secret)
				}
			}
			var out listen.Output = &terminal{a: a, forwardTo: fwd, printSecret: printSecret, keep: keep}
			if format == "json" {
				out = &jsonLines{a: a, printSecret: printSecret, keep: keep}
			}
			return listen.Run(cmd.Context(), cfg, out)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&forwardTo, "forward-to", "f", "", "the URL to POST each event to, e.g. localhost:3000/webhooks")
	f.StringSliceVarP(&events, "events", "e", nil, "only these event types, comma-separated (default: all)")
	f.StringVar(&apiVersion, "api-version", "", "render events in this API version (default: the account's)")
	f.BoolVarP(&latest, "latest", "l", false, "render events in the latest API version")
	f.StringVarP(&headers, "headers", "H", "", `headers to add to each forwarded request: "Key: Value, Key2: Value2"`)
	f.BoolVar(&skipVerify, "skip-verify", false, "accept any certificate of an https --forward-to")
	f.BoolVar(&printSecret, "print-secret", false, "print the signing secret and exit: the one listen last got with login's key on this device, or else from a session it opens, which replaces a listen running with the same key and device")
	f.StringVar(&format, "format", "", "json: print each event as a line of JSON")
	f.StringVar(&device, "device-name", "", "the machine's name, with a secret key (a CLI key has its own)")
	return cmd
}

// forwardURL makes localhost:3000/hook a URL; "" stays "".
func forwardURL(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("--forward-to %q is not an http(s) URL", s)
	}
	return u.String(), nil
}

// parseHeaders reads "Key: Value, Key2: Value2": a comma starts another
// header only where a name and a colon follow it, so a value may hold
// commas (Accept: a, b). The delivery's own headers, PSP-* and
// Content-Type, are not replaced.
func parseHeaders(s string) (http.Header, error) {
	h := http.Header{}
	var parts []string
	for part := range strings.SplitSeq(s, ",") {
		name, _, ok := strings.Cut(part, ":")
		if len(parts) > 0 && (!ok || !headerName.MatchString(strings.TrimSpace(name))) {
			parts[len(parts)-1] += "," + part
			continue
		}
		parts = append(parts, part)
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, ":")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || !headerName.MatchString(k) {
			return nil, fmt.Errorf("--headers %q: want Key: Value", part)
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return nil, fmt.Errorf("--headers %q: a value is one line", k)
		}
		if ck := http.CanonicalHeaderKey(k); ck == "Content-Type" || strings.HasPrefix(ck, "Psp-") {
			return nil, fmt.Errorf("--headers %q: the delivery's own header, as it was signed", k)
		}
		h.Add(k, v)
	}
	return h, nil
}

// headerName is an HTTP header's name (RFC 9110's token).
var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

func splitList(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// terminal shows listen as a person reads it.
type terminal struct {
	a           *app
	forwardTo   string
	printSecret bool
	keep        func(secret string)
	mu          sync.Mutex
}

func (t *terminal) Ready(r listen.Ready) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.keep(r.Secret)
	if t.printSecret {
		fmt.Fprintln(t.a.out, r.Secret)
		return
	}
	fmt.Fprintf(t.a.out, "Ready! Your webhook signing secret is %s (^C to quit)\n", r.Secret)
}

func (t *terminal) Event(e listen.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	at := e.At.Format(time.DateTime)
	fmt.Fprintf(t.a.out, "%s   --> %s [%s]\n", at, e.Type, e.ID)
	if !e.Forward {
		return
	}
	if e.Result.Error != "" {
		fmt.Fprintf(t.a.out, "%s  <--  [ERR] POST %s [%s]: %s\n", at, t.forwardTo, e.ID, e.Result.Detail)
		return
	}
	fmt.Fprintf(t.a.out, "%s  <--  [%d] POST %s [%s]\n", at, e.Result.Status, t.forwardTo, e.ID)
}

func (t *terminal) Reconnecting(err error, wait time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintf(t.a.errOut, "Connection lost (%v); reconnecting in %s…\n", err, wait.Round(time.Second))
}

// jsonLines prints each event's JSON on a line of its own.
type jsonLines struct {
	a           *app
	printSecret bool
	keep        func(secret string)
	mu          sync.Mutex
}

func (j *jsonLines) Ready(r listen.Ready) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.keep(r.Secret)
	if j.printSecret {
		fmt.Fprintln(j.a.out, r.Secret)
		return
	}
	fmt.Fprintf(j.a.errOut, "Ready! Your webhook signing secret is %s (^C to quit)\n", r.Secret)
}

func (j *jsonLines) Event(e listen.Event) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var buf bytes.Buffer
	if err := json.Compact(&buf, e.Body); err != nil {
		buf.Reset()
		b, _ := json.Marshal(string(e.Body))
		buf.Write(b)
	}
	fmt.Fprintln(j.a.out, buf.String())
	if e.Forward {
		if e.Result.Error != "" {
			fmt.Fprintf(j.a.errOut, "%s [ERR] %s: %s\n", e.ID, e.Result.Error, e.Result.Detail)
		} else {
			fmt.Fprintf(j.a.errOut, "%s [%d]\n", e.ID, e.Result.Status)
		}
	}
}

func (j *jsonLines) Reconnecting(err error, wait time.Duration) {
	j.mu.Lock()
	defer j.mu.Unlock()
	fmt.Fprintf(j.a.errOut, "Connection lost (%v); reconnecting in %s…\n", err, wait.Round(time.Second))
}
