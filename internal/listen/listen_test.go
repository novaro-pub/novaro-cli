package listen

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
)

// relay is a fake of webhook-worker's: each socket runs the next script.
type relay struct {
	t       *testing.T
	mu      sync.Mutex
	scripts []func(ctx context.Context, c *websocket.Conn, listen message)
	opens   int
	headers []http.Header
	refuse  func(w http.ResponseWriter) bool
}

func (r *relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.headers = append(r.headers, req.Header.Clone())
	if r.refuse != nil && r.refuse(w) {
		r.mu.Unlock()
		return
	}
	n := r.opens
	r.opens++
	r.mu.Unlock()
	c, err := websocket.Accept(w, req, nil)
	if err != nil {
		r.t.Error(err)
		return
	}
	defer func() { _ = c.CloseNow() }()
	ctx := req.Context()
	var first message
	if err := readJSON(ctx, c, &first); err != nil {
		r.t.Error(err)
		return
	}
	if n >= len(r.scripts) {
		<-ctx.Done()
		return
	}
	r.scripts[n](ctx, c, first)
}

func readJSON(ctx context.Context, c *websocket.Conn, v any) error {
	_, b, err := c.Read(ctx)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeJSON(ctx context.Context, c *websocket.Conn, v any) error {
	b, _ := json.Marshal(v)
	return c.Write(ctx, websocket.MessageText, b)
}

// recorder is an Output that keeps what it was shown.
type recorder struct {
	mu     sync.Mutex
	ready  []Ready
	events []Event
	retry  []error
}

func (o *recorder) Ready(r Ready) { o.mu.Lock(); o.ready = append(o.ready, r); o.mu.Unlock() }
func (o *recorder) Event(e Event) { o.mu.Lock(); o.events = append(o.events, e); o.mu.Unlock() }
func (o *recorder) Reconnecting(err error, _ time.Duration) {
	o.mu.Lock()
	o.retry = append(o.retry, err)
	o.mu.Unlock()
}

func socketOf(t *testing.T, s *httptest.Server) string {
	t.Helper()
	u, err := SocketURL(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

const body = `{"id":"evt_in_1","object":"event","type":"payment.succeeded"}`

func TestListenForwardsAnEventAndAnswersWithTheServersReply(t *testing.T) {
	firstBackoff = 10 * time.Millisecond
	type got struct {
		header http.Header
		body   string
	}
	local := make(chan got, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		local <- got{r.Header.Clone(), string(b)}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, strings.Repeat("x", 3000))
	}))
	defer srv.Close()

	results := make(chan message, 1)
	var listened message
	r := &relay{t: t}
	r.scripts = []func(context.Context, *websocket.Conn, message){
		func(ctx context.Context, c *websocket.Conn, l message) {
			listened = l
			_ = writeJSON(ctx, c, message{Type: "ready", SessionID: "cls_1", EndpointID: "whe_1", Secret: "whsec_1"})
			_ = writeJSON(ctx, c, message{Type: "event", ID: "req1", Body: body, Headers: map[string]string{
				"PSP-Signature": "t=1,v1=ab", "PSP-Event-Id": "evt_in_1", "Content-Type": "application/json", "User-Agent": "NovaroPay/1.0"}})
			var res message
			if err := readJSON(ctx, c, &res); err != nil {
				t.Error(err)
			}
			results <- res
			// The pod stops: a new socket follows.
			_ = writeJSON(ctx, c, message{Type: "error", Code: "server_stopping", Message: "stopping"})
			_ = c.Close(websocket.StatusGoingAway, "server_stopping")
		},
		func(ctx context.Context, c *websocket.Conn, _ message) {
			_ = writeJSON(ctx, c, message{Type: "ready", SessionID: "cls_1", EndpointID: "whe_1", Secret: "whsec_1"})
			_ = writeJSON(ctx, c, message{Type: "error", Code: "session_replaced", Message: "another session"})
			_ = c.Close(websocket.StatusPolicyViolation, "session_replaced")
		},
	}
	api := httptest.NewServer(r)
	defer api.Close()

	out := &recorder{}
	hdr := http.Header{"X-Extra": {"1"}}
	err := Run(t.Context(), Config{URL: socketOf(t, api), Key: "rk_test_in_k", UserAgent: "novaro/test",
		Events: []string{"payment.succeeded"}, APIVersion: "latest", ForwardTo: srv.URL + "/hook", Headers: hdr}, out)
	var e *Error
	if !errors.As(err, &e) || e.Code != "session_replaced" {
		t.Fatalf("Run = %v; want it to stop on session_replaced", err)
	}
	if listened.Type != "listen" || len(listened.Events) != 1 || listened.Events[0] != "payment.succeeded" || listened.APIVersion != "latest" {
		t.Errorf("listen message %+v", listened)
	}
	if h := r.headers[0]; h.Get("Authorization") != "Bearer rk_test_in_k" || h.Get("User-Agent") != "novaro/test" {
		t.Errorf("open headers %v", h)
	}
	g := <-local
	if g.body != body || g.header.Get("PSP-Signature") != "t=1,v1=ab" || g.header.Get("PSP-Event-Id") != "evt_in_1" || g.header.Get("X-Extra") != "1" {
		t.Errorf("forwarded %v %q", g.header, g.body)
	}
	res := <-results
	if res.Type != "result" || res.ID != "req1" || res.Status != 201 || len(res.Body) != bodyLimit || res.Error != "" {
		t.Errorf("result %+v (body %d bytes)", res, len(res.Body))
	}
	if r.opens != 2 || len(out.ready) != 2 || out.ready[0].Secret != "whsec_1" {
		t.Errorf("opens %d, ready %+v", r.opens, out.ready)
	}
	if len(out.events) != 1 || out.events[0].ID != "evt_in_1" || out.events[0].Type != "payment.succeeded" {
		t.Errorf("events %+v", out.events)
	}
	if len(out.retry) != 1 {
		t.Errorf("reconnects %v", out.retry)
	}
}

func TestListenAnswersAServerItCouldNotReach(t *testing.T) {
	forwardWait = 200 * time.Millisecond
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer slow.Close()
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()

	for _, c := range []struct {
		to   string
		want string
	}{{downURL, "connect"}, {slow.URL, "timeout"}} {
		results := make(chan message, 1)
		r := &relay{t: t}
		r.scripts = []func(context.Context, *websocket.Conn, message){
			func(ctx context.Context, conn *websocket.Conn, _ message) {
				_ = writeJSON(ctx, conn, message{Type: "ready", Secret: "whsec_1"})
				_ = writeJSON(ctx, conn, message{Type: "event", ID: "r", Body: body})
				var res message
				_ = readJSON(ctx, conn, &res)
				results <- res
				_ = writeJSON(ctx, conn, message{Type: "error", Code: "session_replaced"})
				_ = conn.Close(websocket.StatusPolicyViolation, "session_replaced")
			},
		}
		api := httptest.NewServer(r)
		_ = Run(t.Context(), Config{URL: socketOf(t, api), Key: "k", ForwardTo: c.to}, &recorder{})
		api.Close()
		if res := <-results; res.Error != c.want || res.Status != 0 {
			t.Errorf("%s: result %+v; want error %s", c.to, res, c.want)
		}
	}
}

func TestListenWithoutForwardToTakesEveryEvent(t *testing.T) {
	results := make(chan message, 1)
	r := &relay{t: t}
	r.scripts = []func(context.Context, *websocket.Conn, message){
		func(ctx context.Context, conn *websocket.Conn, _ message) {
			_ = writeJSON(ctx, conn, message{Type: "ready", Secret: "whsec_1"})
			_ = writeJSON(ctx, conn, message{Type: "event", ID: "r", Body: body})
			var res message
			_ = readJSON(ctx, conn, &res)
			results <- res
			_ = conn.Close(websocket.StatusPolicyViolation, "session_replaced")
		},
	}
	api := httptest.NewServer(r)
	defer api.Close()
	out := &recorder{}
	_ = Run(t.Context(), Config{URL: socketOf(t, api), Key: "k"}, out)
	if res := <-results; res.Status != 200 {
		t.Errorf("result %+v", res)
	}
	if len(out.events) != 1 || out.events[0].Forward {
		t.Errorf("events %+v", out.events)
	}
}

func TestListenStopsOnARefusalAndWaitsOutARateLimit(t *testing.T) {
	firstBackoff = 10 * time.Millisecond
	r := &relay{t: t}
	r.refuse = func(w http.ResponseWriter) bool {
		if r.opens == 0 && len(r.headers) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":{"type":"rate_limit_error","code":"rate_limit","message":"Too many"}}`)
			return true
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"type":"invalid_request_error","message":"Invalid API key provided."}}`)
		return true
	}
	api := httptest.NewServer(r)
	defer api.Close()
	out := &recorder{}
	start := time.Now()
	err := Run(t.Context(), Config{URL: socketOf(t, api), Key: "k"}, out)
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusUnauthorized || e.Message != "Invalid API key provided." {
		t.Fatalf("Run = %v", err)
	}
	if time.Since(start) < time.Second {
		t.Errorf("reopened after %s; want Retry-After's 1 s", time.Since(start))
	}
	if len(out.retry) != 1 {
		t.Errorf("reconnects %v", out.retry)
	}
}

func TestListenRefusedOpenStops(t *testing.T) {
	r := &relay{t: t}
	r.scripts = []func(context.Context, *websocket.Conn, message){
		func(ctx context.Context, conn *websocket.Conn, _ message) {
			_ = writeJSON(ctx, conn, message{Type: "error", Code: "parameter_invalid", Message: "No such API version"})
			_ = conn.Close(websocket.StatusPolicyViolation, "parameter_invalid")
		},
	}
	api := httptest.NewServer(r)
	defer api.Close()
	err := Run(t.Context(), Config{URL: socketOf(t, api), Key: "k", APIVersion: "nope"}, &recorder{})
	if err == nil || err.Error() != "No such API version (parameter_invalid)" {
		t.Fatalf("Run = %v", err)
	}
}

func TestPrintSecretStopsAfterReady(t *testing.T) {
	r := &relay{t: t}
	r.scripts = []func(context.Context, *websocket.Conn, message){
		func(ctx context.Context, conn *websocket.Conn, _ message) {
			_ = writeJSON(ctx, conn, message{Type: "ready", Secret: "whsec_9"})
			// Read, as the relay does, so the CLI's close is answered.
			_, _, _ = conn.Read(ctx)
		},
	}
	api := httptest.NewServer(r)
	defer api.Close()
	out := &recorder{}
	if err := Run(t.Context(), Config{URL: socketOf(t, api), Key: "k", Once: true}, out); err != nil {
		t.Fatal(err)
	}
	if len(out.ready) != 1 || out.ready[0].Secret != "whsec_9" {
		t.Errorf("%+v", out.ready)
	}
}

func TestSocketURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://api.example.com": "wss://api.example.com/cli/listen",
		"http://localhost:28081/": "ws://localhost:28081/cli/listen",
	} {
		if got, err := SocketURL(in); err != nil || got != want {
			t.Errorf("SocketURL(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := SocketURL("ftp://x"); err == nil {
		t.Error("ftp accepted")
	}
}

// Ctrl-C ends listen with the context's error, after a close message the
// relay reads, not a dropped socket.
func TestCtrlCClosesTheSocket(t *testing.T) {
	closed := make(chan websocket.StatusCode, 1)
	r := &relay{t: t}
	r.scripts = []func(context.Context, *websocket.Conn, message){
		func(ctx context.Context, conn *websocket.Conn, _ message) {
			_ = writeJSON(ctx, conn, message{Type: "ready", Secret: "whsec_1"})
			_, _, err := conn.Read(ctx)
			closed <- websocket.CloseStatus(err)
		},
	}
	api := httptest.NewServer(r)
	defer api.Close()
	ctx, cancel := context.WithCancel(t.Context())
	out := &readyThen{recorder: &recorder{}, then: cancel}
	err := Run(ctx, Config{URL: socketOf(t, api), Key: "k"}, out)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v; want context.Canceled", err)
	}
	if code := <-closed; code != websocket.StatusNormalClosure {
		t.Errorf("the relay read %v; want a normal close", code)
	}
}

// readyThen calls then once the relay is ready.
type readyThen struct {
	*recorder
	then func()
}

func (o *readyThen) Ready(r Ready) { o.recorder.Ready(r); o.then() }

// A relay that goes quiet (no ping, no message) past pingGap is left, and
// a new socket opened.
func TestASilentRelayIsLeft(t *testing.T) {
	pingGap, firstBackoff = 300*time.Millisecond, 10*time.Millisecond
	defer func() { pingGap = 75 * time.Second }()
	r := &relay{t: t}
	r.scripts = []func(context.Context, *websocket.Conn, message){
		func(ctx context.Context, conn *websocket.Conn, _ message) {
			_ = writeJSON(ctx, conn, message{Type: "ready", Secret: "whsec_1"})
			<-ctx.Done() // silent: no ping, no close
		},
		func(ctx context.Context, conn *websocket.Conn, _ message) {
			_ = writeJSON(ctx, conn, message{Type: "ready", Secret: "whsec_1"})
			_ = writeJSON(ctx, conn, message{Type: "error", Code: "session_replaced"})
			_ = conn.Close(websocket.StatusPolicyViolation, "session_replaced")
		},
	}
	api := httptest.NewServer(r)
	defer api.Close()
	out := &recorder{}
	start := time.Now()
	err := Run(t.Context(), Config{URL: socketOf(t, api), Key: "k"}, out)
	var e *Error
	if !errors.As(err, &e) || e.Code != "session_replaced" || len(out.retry) != 1 {
		t.Fatalf("Run = %v, reconnects %v", err, out.retry)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("left the silent relay after %s", d)
	}
}

func TestClip(t *testing.T) {
	euro := strings.Repeat("€", 1000) // 3000 bytes, 2048 inside a character
	if got := clip([]byte(euro), 2048); len(got) > 2048 || !utf8.ValidString(got) || len(got) != 2046 {
		t.Errorf("3-byte characters: %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
	bin := make([]byte, 2048)
	for i := range bin {
		bin[i] = 0xff
	}
	if got := clip(bin, 2048); len(got) > 2048 || !utf8.ValidString(got) {
		t.Errorf("binary: %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
	if b, _ := json.Marshal(clip(bin, 2048)); len(b) > 2048+2 {
		t.Errorf("binary as JSON: %d bytes", len(b))
	}
	// A read of the limit and a character more: the broken tail goes, no
	// replacement character in its place.
	cut := []byte(strings.Repeat("€", 700))[:2050] // 683 characters and 2 bytes of one
	if got := clip(cut, 2048); len(got) != 2046 || strings.ContainsRune(got, utf8.RuneError) {
		t.Errorf("a cut read: %d bytes, %q at its end", len(got), got[len(got)-3:])
	}
	if got := clip([]byte("ok"), 2048); got != "ok" {
		t.Errorf("%q", got)
	}
}
