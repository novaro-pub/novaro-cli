package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"novaro-cli/internal/config"
)

const testKey = "sk_test_in_0123456789abcdefghijABCDEFGHIJ0123456789xyz"

// fakeKeyring is the OS keychain in memory; broken refuses every write,
// as a server with no keychain does.
type fakeKeyring struct {
	mu     sync.Mutex
	m      map[string]string
	broken bool
}

func (k *fakeKeyring) Set(s, u, p string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.broken {
		return errors.New("no keychain")
	}
	k.m[s+"|"+u] = p
	return nil
}

func (k *fakeKeyring) Get(s, u string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.broken {
		return "", errors.New("no keychain")
	}
	v, ok := k.m[s+"|"+u]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (k *fakeKeyring) Delete(s, u string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.broken {
		return errors.New("no keychain")
	}
	if _, ok := k.m[s+"|"+u]; !ok {
		return keyring.ErrNotFound
	}
	delete(k.m, s+"|"+u)
	return nil
}

type harness struct {
	a       *app
	out     *bytes.Buffer
	errOut  *bytes.Buffer
	keyring *fakeKeyring
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	t.Setenv("NOVARO_API_BASE", "")
	t.Setenv("NOVARO_API_KEY", "")
	kr := &fakeKeyring{m: map[string]string{}}
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	return &harness{
		a: &app{
			build: Build{Version: "1.2.3", Commit: "abc", Date: "today"},
			out:   out, errOut: errOut,
			store: &config.Store{Path: filepath.Join(t.TempDir(), "novaro", "config.json"), Keyring: kr},
			now:   time.Now,
		},
		out: out, errOut: errOut, keyring: kr,
	}
}

func (h *harness) run(t *testing.T, args ...string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	// A command's flags live on it: a new tree for every run.
	h.a.apiKey, h.a.apiBase = "", ""
	root := h.a.root()
	root.SetArgs(args)
	return root.ExecuteContext(ctx)
}

// request is one call the fake API got.
type request struct {
	Method, Path, Query string
	Header              http.Header
	Body                map[string]any
}

// fakeAPI answers each path with handle's and records every call.
type fakeAPI struct {
	mu    sync.Mutex
	calls []request
}

func (f *fakeAPI) server(t *testing.T, handle func(r request) (int, any)) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		req := request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header.Clone()}
		if len(b) > 0 {
			if err := json.Unmarshal(b, &req.Body); err != nil {
				t.Errorf("%s %s: body %q is not JSON", r.Method, r.URL.Path, b)
			}
		}
		f.mu.Lock()
		f.calls = append(f.calls, req)
		f.mu.Unlock()
		status, out := handle(req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(s.Close)
	return s
}

func (f *fakeAPI) all() []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]request(nil), f.calls...)
}

func apiError(code, message string) map[string]any {
	return map[string]any{"error": map[string]any{"type": "invalid_request_error", "code": code, "message": message}}
}

func TestLoginPairsInTheBrowserAndKeepsTheKeyInTheKeychain(t *testing.T) {
	pollEvery = 5 * time.Millisecond
	h := newHarness(t)
	var f fakeAPI
	polls := 0
	s := f.server(t, func(r request) (int, any) {
		switch r.Path {
		case "/cli/pairings/in":
			return http.StatusOK, map[string]any{"id": "clp_in_1", "code": "ABCD-EFGH", "poll_secret": "ps_1",
				"url": "http://portal/cli/pair?code=ABCD-EFGH", "expires_at": strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10), "device_name": "box"}
		case "/cli/pairings/in/clp_in_1/poll":
			if polls++; polls < 3 {
				return http.StatusOK, map[string]any{"status": "pending"}
			}
			return http.StatusOK, map[string]any{"status": "confirmed", "api_key": "rk_test_in_ABCDEFGHrest",
				"key_prefix": "rk_test_in_ABCDEFGH", "key_expires_at": "1900000000"}
		}
		return http.StatusNotFound, apiError("resource_missing", "no")
	})
	if err := h.run(t, "login", "--api-base", s.URL, "--device-name", "box", "--no-browser"); err != nil {
		t.Fatal(err)
	}
	calls := f.all()
	if got := calls[0].Body["device_name"]; got != "box" {
		t.Errorf("device_name %v", got)
	}
	if calls[0].Header.Get("Authorization") != "" {
		t.Error("pairing sent a key")
	}
	for _, c := range calls[1:] {
		if c.Body["poll_secret"] != "ps_1" {
			t.Errorf("poll body %v", c.Body)
		}
	}
	if !strings.Contains(h.out.String(), "ABCD-EFGH") || !strings.Contains(h.out.String(), "http://portal/cli/pair?code=ABCD-EFGH") {
		t.Errorf("output %q: want the code and the link", h.out)
	}
	p, key, err := h.a.store.Load()
	if err != nil || key != "rk_test_in_ABCDEFGHrest" {
		t.Fatalf("Load = %q, %v", key, err)
	}
	if p.APIBase != s.URL || p.Market != "in" || p.DeviceName != "box" || p.KeyExpiresAt != 1900000000 || p.Key != "" {
		t.Errorf("profile %+v: want the key in the keychain only", p)
	}
	b, _ := os.ReadFile(h.a.store.Path)
	if strings.Contains(string(b), "rk_test_in_ABCDEFGHrest") {
		t.Error("the key is in the config file though the keychain took it")
	}
}

func TestLoginStopsWhenThePairingEnds(t *testing.T) {
	pollEvery = 5 * time.Millisecond
	h := newHarness(t)
	var f fakeAPI
	s := f.server(t, func(r request) (int, any) {
		if r.Path == "/cli/pairings/in" {
			return http.StatusOK, map[string]any{"id": "clp_in_1", "code": "C", "poll_secret": "p", "url": "u", "expires_at": time.Now().Add(time.Minute).Unix()}
		}
		return http.StatusNotFound, apiError("resource_missing", "No such pairing")
	})
	err := h.run(t, "login", "--api-base", s.URL, "--no-browser")
	if err == nil || !strings.Contains(err.Error(), "run novaro login again") {
		t.Fatalf("err %v", err)
	}
	if _, _, err := h.a.store.Load(); !errors.Is(err, config.ErrNotLoggedIn) {
		t.Errorf("Load after a failed login: %v", err)
	}
}

func TestLoginWithAKeyKeepsItInTheFileWhenNoKeychainTakesIt(t *testing.T) {
	h := newHarness(t)
	h.keyring.broken = true
	if err := h.run(t, "login", "--api-key", testKey, "--api-base", "https://x"); err != nil {
		t.Fatal(err)
	}
	p, key, err := h.a.store.Load()
	if err != nil || key != testKey || p.Market != "in" || p.KeyPrefix != "sk_test_in_01234567" {
		t.Fatalf("%+v %q %v", p, key, err)
	}
	st, err := os.Stat(h.a.store.Path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config file %v %v; want 0600", st.Mode(), err)
	}
	if err := h.run(t, "logout"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.a.store.Load(); !errors.Is(err, config.ErrNotLoggedIn) {
		t.Errorf("after logout: %v", err)
	}
}

func TestLoginRefusesALiveKey(t *testing.T) {
	h := newHarness(t)
	err := h.run(t, "login", "--api-key", "sk_live_in_0123456789abcdef")
	if err == nil || !strings.Contains(err.Error(), "test keys only") {
		t.Fatalf("err %v", err)
	}
}

func TestAnExpiredKeyAsksForLogin(t *testing.T) {
	h := newHarness(t)
	if _, err := h.a.store.Save(config.Profile{APIBase: "https://x", Market: "in", KeyPrefix: "rk_test_in_AAAAAAAA", KeyExpiresAt: time.Now().Add(-time.Hour).Unix()}, "rk_test_in_AAAAAAAAzz"); err != nil {
		t.Fatal(err)
	}
	err := h.run(t, "events", "list")
	if err == nil || !strings.Contains(err.Error(), "run novaro login again") {
		t.Fatalf("err %v", err)
	}
}

func TestTriggerMakesATestPaymentAndConfirmsItWithTheMagicUTR(t *testing.T) {
	h := newHarness(t)
	var f fakeAPI
	s := f.server(t, func(r request) (int, any) {
		switch r.Path {
		case "/payments":
			return http.StatusCreated, map[string]any{"id": "pay_in_1", "status": "awaiting_payer"}
		case "/payments/pay_in_1/confirmations":
			return http.StatusOK, map[string]any{"id": "pay_in_1", "status": "succeeded"}
		}
		return http.StatusNotFound, apiError("resource_missing", "no")
	})
	if err := h.run(t, "trigger", "payment.succeeded", "--api-key", testKey, "--api-base", s.URL,
		"--override", "amount=50000", "--override", "metadata.order=42", "--override", "customer.email=a@b.c"); err != nil {
		t.Fatal(err)
	}
	calls := f.all()
	if len(calls) != 2 {
		t.Fatalf("calls %+v", calls)
	}
	create, confirm := calls[0], calls[1]
	if create.Method != http.MethodPost || create.Header.Get("Authorization") != "Bearer "+testKey || create.Header.Get("Idempotency-Key") == "" {
		t.Errorf("create %+v", create)
	}
	b := create.Body
	if b["amount"] != float64(50000) || b["currency"] != "INR" || !strings.HasPrefix(b["merchant_reference"].(string), "novaro_trigger_") {
		t.Errorf("create body %v", b)
	}
	if c := b["customer"].(map[string]any); c["id"] != "novaro_cli" || c["email"] != "a@b.c" {
		t.Errorf("customer %v", c)
	}
	if m := b["metadata"].(map[string]any); m["order"] != "42" {
		t.Errorf("metadata %v: want strings", m)
	}
	if pm := b["payment_method_data"].(map[string]any); pm["type"] != "upi" {
		t.Errorf("payment_method_data %v", pm)
	}
	if confirm.Body["utr"] != "000000000001" || confirm.Header.Get("Idempotency-Key") == create.Header.Get("Idempotency-Key") {
		t.Errorf("confirm %+v", confirm)
	}
}

func TestTriggerProcessingUsesAnOrdinaryUTR(t *testing.T) {
	for range 100 {
		u := ordinaryUTR()
		if len(u) != 12 || strings.HasPrefix(u, "0") {
			t.Fatalf("UTR %q", u)
		}
	}
}

func TestTriggerOnlyMakesWhatItKnows(t *testing.T) {
	h := newHarness(t)
	err := h.run(t, "trigger", "payment.expired", "--api-key", testKey)
	if err == nil || !strings.Contains(err.Error(), "--list") {
		t.Fatalf("err %v", err)
	}
	if err := h.run(t, "trigger", "--list"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"payment.created", "payment.processing", "payment.succeeded", "payment.failed"} {
		if !strings.Contains(h.out.String(), n) {
			t.Errorf("--list misses %s: %q", n, h.out)
		}
	}
	if err := h.run(t, "trigger", "payment.created", "--api-key", "sk_live_in_0123456789abcdef"); err == nil || !strings.Contains(err.Error(), "test mode only") {
		t.Errorf("a live key: %v", err)
	}
}

func TestEvents(t *testing.T) {
	h := newHarness(t)
	var f fakeAPI
	s := f.server(t, func(r request) (int, any) {
		switch r.Path {
		case "/events":
			return http.StatusOK, map[string]any{"object": "list", "data": []any{}, "has_more": false, "url": "/events"}
		case "/events/evt_in_1":
			return http.StatusOK, map[string]any{"id": "evt_in_1", "object": "event"}
		case "/events/evt_in_1/retry":
			return http.StatusOK, map[string]any{"id": "evt_in_1", "object": "event"}
		}
		return http.StatusNotFound, apiError("resource_missing", "No such event: 'evt_in_2'")
	})
	base := []string{"--api-key", testKey, "--api-base", s.URL}
	if err := h.run(t, append([]string{"events", "list", "--limit", "3", "--type", "payment.*", "--delivery-success", "false"}, base...)...); err != nil {
		t.Fatal(err)
	}
	if q := f.all()[0].Query; q != "delivery_success=false&limit=3&type=payment.%2A" {
		t.Errorf("query %q", q)
	}
	if !strings.Contains(h.out.String(), `"object": "list"`) {
		t.Errorf("output %q", h.out)
	}
	if err := h.run(t, append([]string{"events", "retrieve", "evt_in_1"}, base...)...); err != nil {
		t.Fatal(err)
	}
	if err := h.run(t, append([]string{"events", "resend", "evt_in_1", "--webhook-endpoint", "whe_in_1"}, base...)...); err != nil {
		t.Fatal(err)
	}
	last := f.all()[2]
	if last.Method != http.MethodPost || last.Body["webhook_endpoint"] != "whe_in_1" || last.Header.Get("Idempotency-Key") != "" {
		t.Errorf("resend %+v", last)
	}
	err := h.run(t, append([]string{"events", "retrieve", "evt_in_2"}, base...)...)
	if err == nil || err.Error() != "No such event: 'evt_in_2' (resource_missing)" {
		t.Errorf("err %v", err)
	}
	if err := h.run(t, "events", "list", "--live", "--api-key", testKey); err == nil || !strings.Contains(err.Error(), "sk_live_") {
		t.Errorf("--live with a test key: %v", err)
	}
	if err := h.run(t, "events", "list", "--api-key", "sk_live_in_0123456789abcdef"); err == nil || !strings.Contains(err.Error(), "add --live") {
		t.Errorf("a live key without --live: %v", err)
	}
}

func TestVersion(t *testing.T) {
	h := newHarness(t)
	if err := h.run(t, "version"); err != nil {
		t.Fatal(err)
	}
	if got := h.out.String(); got != "novaro version 1.2.3 (commit abc, built today)\n" {
		t.Errorf("%q", got)
	}
}

// Where no keychain answers, logout still removes the key, which is in the
// file, and says nothing went wrong; a broken file is removed too.
func TestLogoutWithoutAKeychain(t *testing.T) {
	h := newHarness(t)
	h.keyring.broken = true
	if err := h.run(t, "login", "--api-key", testKey, "--api-base", "https://x"); err != nil {
		t.Fatal(err)
	}
	if err := h.run(t, "logout"); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := os.Stat(h.a.store.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the file with the key is still there: %v", err)
	}
	h.keyring.broken = false
	if err := os.MkdirAll(filepath.Dir(h.a.store.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.a.store.Path, []byte("{nonsense"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.run(t, "logout"); err != nil {
		t.Fatalf("logout of a broken file: %v", err)
	}
	if _, err := os.Stat(h.a.store.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the broken file is still there: %v", err)
	}
}

// A second login replaces the key in the keychain, whatever its address:
// one entry, never an orphan of the first.
func TestASecondLoginReplacesTheKey(t *testing.T) {
	h := newHarness(t)
	if err := h.run(t, "login", "--api-key", testKey, "--api-base", "https://a"); err != nil {
		t.Fatal(err)
	}
	other := "rk_test_in_ZYXWVUTSrest"
	if err := h.run(t, "login", "--api-key", other, "--api-base", "https://b"); err != nil {
		t.Fatal(err)
	}
	if len(h.keyring.m) != 1 {
		t.Fatalf("keychain %v; want one entry", h.keyring.m)
	}
	if _, key, err := h.a.store.Load(); err != nil || key != other {
		t.Fatalf("Load = %q, %v", key, err)
	}
}

// Login's key goes to login's address alone, and no key goes over plain
// http but to this machine.
func TestTheKeyGoesToItsAddressOnly(t *testing.T) {
	h := newHarness(t)
	if err := h.run(t, "login", "--api-key", testKey, "--api-base", "https://api.example.com"); err != nil {
		t.Fatal(err)
	}
	err := h.run(t, "events", "list", "--api-base", "https://evil.example.com")
	if err == nil || !strings.Contains(err.Error(), "login's key is for https://api.example.com") {
		t.Errorf("another --api-base: %v", err)
	}
	t.Setenv("NOVARO_API_BASE", "http://localhost:28081")
	if err := h.run(t, "events", "list"); err == nil || !strings.Contains(err.Error(), "login's key is for") {
		t.Errorf("another $NOVARO_API_BASE: %v", err)
	}
	t.Setenv("NOVARO_API_BASE", "")
	for base, want := range map[string]string{"http://api.example.com": "plain http", "ftp://x": "not http(s)", "nonsense": "not a URL"} {
		if err := h.run(t, "events", "list", "--api-key", testKey, "--api-base", base); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v; want %q", base, err, want)
		}
	}
	for _, base := range []string{"http://localhost:1", "http://127.0.0.1:1", "http://api.localhost:1", "http://[::1]:1"} {
		if err := checkBase(base); err != nil {
			t.Errorf("%s: %v", base, err)
		}
	}
}

func TestSafeLink(t *testing.T) {
	for link, want := range map[string]bool{
		"https://portal.example.com/cli/pair?code=A": true,
		"http://portal.localhost:5173/cli/pair":      true,
		"http://portal.example.com/cli/pair":         false,
		"file:///etc/passwd":                         false,
		`C:\Windows\x.exe`:                           false,
		"/Applications/Calculator.app":               false,
		"javascript:alert(1)":                        false,
	} {
		if got := safeLink(link); got != want {
			t.Errorf("safeLink(%q) = %v", link, got)
		}
	}
}

func TestNovaroAPIKey(t *testing.T) {
	h := newHarness(t)
	var f fakeAPI
	s := f.server(t, func(request) (int, any) {
		return http.StatusOK, map[string]any{"object": "list", "data": []any{}}
	})
	t.Setenv("NOVARO_API_KEY", testKey)
	if err := h.run(t, "events", "list", "--api-base", s.URL); err != nil {
		t.Fatal(err)
	}
	if got := f.all()[0].Header.Get("Authorization"); got != "Bearer "+testKey {
		t.Errorf("Authorization %q", got)
	}
	h.out.Reset()
	if err := h.run(t, "--help"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h.out.String(), testKey) {
		t.Error("--help printed the key")
	}
}

// version needs no config directory.
func TestVersionWithoutAConfigDirectory(t *testing.T) {
	h := newHarness(t)
	h.a.store, h.a.storeErr = nil, errors.New("no config directory")
	if err := h.run(t, "version"); err != nil {
		t.Fatal(err)
	}
	if err := h.run(t, "logout"); err == nil {
		t.Error("logout without a config directory passed")
	}
}

func TestParseHeaders(t *testing.T) {
	h, err := parseHeaders("Accept: a, b, X-Trace: 1,Host: local.test")
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("Accept") != "a, b" || h.Get("X-Trace") != "1" || h.Get("Host") != "local.test" {
		t.Errorf("%v", h)
	}
	for _, bad := range []string{"nocolon", "Bad Name: x", "PSP-Signature: t=1", "Content-Type: text/plain", "X: a\rb"} {
		if _, err := parseHeaders(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// --print-secret prints the secret listen last got with login's key on
// this device, and opens no session, which would replace a running
// listen's; a secret of another key or device is not that one's.
func TestPrintSecretReadsTheLastOne(t *testing.T) {
	h := newHarness(t)
	const rk = "rk_test_in_ABCDEFGHrest"
	if err := h.run(t, "login", "--api-key", rk, "--api-base", "https://unreachable.invalid"); err != nil {
		t.Fatal(err)
	}
	if err := h.a.store.SetListenSecret(prefixOf(rk), "", "whsec_kept"); err != nil {
		t.Fatal(err)
	}
	h.out.Reset()
	if err := h.run(t, "listen", "--print-secret"); err != nil {
		t.Fatal(err)
	}
	if got := h.out.String(); got != "whsec_kept\n" {
		t.Errorf("printed %q", got)
	}
	// A listen of an earlier login's key keeps its secret to itself.
	if err := h.a.store.SetListenSecret("rk_test_in_OTHERKEY", "", "whsec_other"); err != nil {
		t.Fatal(err)
	}
	if p, _ := h.a.store.Profile(); p.ListenSecret != "whsec_kept" {
		t.Errorf("another key's secret was kept: %+v", p)
	}

	// A secret key's: this machine's device, or another one named.
	h = newHarness(t)
	if err := h.run(t, "login", "--api-key", testKey, "--api-base", "https://unreachable.invalid"); err != nil {
		t.Fatal(err)
	}
	p, key, _ := h.a.store.Load()
	if p.DeviceName == "" {
		t.Fatal("login kept no device name")
	}
	// The name login kept, not the host's now (one that changes with the
	// network would make a new device with a new secret).
	p.DeviceName = "kept-at-login"
	if _, err := h.a.store.Save(p, key); err != nil {
		t.Fatal(err)
	}
	if err := h.a.store.SetListenSecret(prefixOf(testKey), p.DeviceName, "whsec_here"); err != nil {
		t.Fatal(err)
	}
	h.out.Reset()
	if err := h.run(t, "listen", "--print-secret"); err != nil || h.out.String() != "whsec_here\n" {
		t.Errorf("this device: %q, %v", h.out, err)
	}
	h.out.Reset()
	// Another device has no secret kept: it opens a session (here, to an
	// address that does not answer) rather than print this one's.
	if err := h.run(t, "listen", "--print-secret", "--device-name", "ci-box"); err == nil || strings.Contains(h.out.String(), "whsec_here") {
		t.Errorf("another device: printed %q, %v", h.out, err)
	}
}

// Logout where the keychain cannot be reached: a key kept in it stays,
// and so does the file, to run logout again; a broken file goes.
func TestLogoutWhenTheKeychainFails(t *testing.T) {
	h := newHarness(t)
	if err := h.run(t, "login", "--api-key", testKey, "--api-base", "https://x"); err != nil {
		t.Fatal(err)
	}
	h.keyring.broken = true
	if err := h.run(t, "logout"); err == nil || !strings.Contains(err.Error(), "run novaro logout again") {
		t.Fatalf("logout: %v", err)
	}
	if _, err := os.Stat(h.a.store.Path); err != nil {
		t.Fatalf("the file went with the key still in the keychain: %v", err)
	}
	if err := os.WriteFile(h.a.store.Path, []byte("{nonsense"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.run(t, "logout"); err != nil {
		t.Fatalf("logout of a broken file, no keychain: %v", err)
	}
	if _, err := os.Stat(h.a.store.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the broken file is still there: %v", err)
	}
}

// An exported NOVARO_API_KEY is for the other commands: login pairs in the
// browser all the same.
func TestLoginPairsWhateverTheEnvironmentHolds(t *testing.T) {
	pollEvery = 5 * time.Millisecond
	h := newHarness(t)
	t.Setenv("NOVARO_API_KEY", "sk_live_in_0123456789abcdef")
	var f fakeAPI
	s := f.server(t, func(r request) (int, any) {
		if r.Path == "/cli/pairings/in" {
			return http.StatusOK, map[string]any{"id": "clp_in_1", "code": "C", "poll_secret": "p", "url": "u"}
		}
		return http.StatusOK, map[string]any{"status": "confirmed", "api_key": "rk_test_in_ABCDEFGHrest", "key_prefix": "rk_test_in_ABCDEFGH"}
	})
	if err := h.run(t, "login", "--api-base", s.URL, "--no-browser"); err != nil {
		t.Fatal(err)
	}
	if _, key, err := h.a.store.Load(); err != nil || key != "rk_test_in_ABCDEFGHrest" {
		t.Fatalf("Load = %q, %v", key, err)
	}
}

// login --api-key keeps the device named, so a CI runner whose host name
// changes every job keeps one device and one listen secret.
func TestLoginWithAKeyKeepsTheDeviceNamed(t *testing.T) {
	h := newHarness(t)
	if err := h.run(t, "login", "--api-key", testKey, "--api-base", "https://x", "--device-name", "ci"); err != nil {
		t.Fatal(err)
	}
	if p, _ := h.a.store.Profile(); p.DeviceName != "ci" {
		t.Errorf("device %q", p.DeviceName)
	}
}

// --api-key "" is no key, not $NOVARO_API_KEY's.
func TestAnEmptyAPIKeyFlagIsNotTheEnvironments(t *testing.T) {
	h := newHarness(t)
	t.Setenv("NOVARO_API_KEY", testKey)
	if err := h.run(t, "login", "--api-key", "", "--api-base", "https://x"); err == nil {
		t.Fatal("login kept $NOVARO_API_KEY for an empty --api-key")
	}
	if _, _, err := h.a.store.Load(); !errors.Is(err, config.ErrNotLoggedIn) {
		t.Errorf("Load: %v", err)
	}
}

func TestExitCodes(t *testing.T) {
	if exitCode(os.Interrupt) != 130 || exitCode(syscall.SIGTERM) != 143 {
		t.Errorf("%d %d", exitCode(os.Interrupt), exitCode(syscall.SIGTERM))
	}
}
