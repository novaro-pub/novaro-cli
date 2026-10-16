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
	"strings"
	"sync"
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
	v, ok := k.m[s+"|"+u]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (k *fakeKeyring) Delete(s, u string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
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
				"url": "http://portal/cli/pair?code=ABCD-EFGH", "expires_at": time.Now().Add(10 * time.Minute).Unix(), "device_name": "box"}
		case "/cli/pairings/in/clp_in_1/poll":
			if polls++; polls < 3 {
				return http.StatusOK, map[string]any{"status": "pending"}
			}
			return http.StatusOK, map[string]any{"status": "confirmed", "api_key": "rk_test_in_ABCDEFGHrest",
				"key_prefix": "rk_test_in_ABCDEFGH", "key_expires_at": 1900000000}
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
	if err := h.run(t, "login", "--api-key", testKey, "--api-base", "http://x"); err != nil {
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
	if _, err := h.a.store.Save(config.Profile{APIBase: "http://x", Market: "in", KeyPrefix: "rk_test_in_AAAAAAAA", KeyExpiresAt: time.Now().Add(-time.Hour).Unix()}, "rk_test_in_AAAAAAAAzz"); err != nil {
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
	if last.Method != http.MethodPost || last.Body["webhook_endpoint"] != "whe_in_1" || last.Header.Get("Idempotency-Key") == "" {
		t.Errorf("resend %+v", last)
	}
	err := h.run(t, append([]string{"events", "retrieve", "evt_in_2"}, base...)...)
	if err == nil || err.Error() != "No such event: 'evt_in_2' (resource_missing)" {
		t.Errorf("err %v", err)
	}
	if err := h.run(t, "events", "list", "--live", "--api-key", testKey); err == nil || !strings.Contains(err.Error(), "sk_live_") {
		t.Errorf("--live with a test key: %v", err)
	}
	if err := h.run(t, "events", "list", "--api-key", "sk_live_in_0123456789abcdef"); err == nil || !strings.Contains(err.Error(), "test mode only") {
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
