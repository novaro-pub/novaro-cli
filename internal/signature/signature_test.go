package signature

import (
	"errors"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	const secret = "whsec_test"
	body := []byte(`{"id":"evt_in_1"}`)
	now := time.Unix(1_760_000_000, 0)
	h := Sign(secret, now, body)
	if h != "t=1760000000,v1="+mac(secret, "1760000000", body) {
		t.Fatalf("header %q", h)
	}
	for _, c := range []struct {
		name   string
		header string
		body   []byte
		secret string
		at     time.Time
		want   error
	}{
		{"ok", h, body, secret, now, nil},
		{"one of two secrets", "t=1760000000,v1=00ff," + h[len("t=1760000000,"):], body, secret, now, nil},
		{"other body", h, []byte(`{}`), secret, now, ErrMismatch},
		{"other secret", h, body, "whsec_other", now, ErrMismatch},
		{"too old", h, body, secret, now.Add(Tolerance + time.Second), ErrTooOld},
		{"from the future", h, body, secret, now.Add(-Tolerance - time.Second), ErrTooOld},
		{"no t", "v1=" + mac(secret, "1760000000", body), body, secret, now, ErrMalformed},
		{"no v1", "t=1760000000", body, secret, now, ErrMalformed},
		{"garbage", "nonsense", body, secret, now, ErrMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := Verify(c.header, c.body, c.secret, Tolerance, c.at); !errors.Is(err, c.want) {
				t.Fatalf("Verify = %v; want %v", err, c.want)
			}
		})
	}
}

// The docs' signed delivery (Signatures page): a header signed with two
// secrets, each of which verifies it, as webhook-worker sends it; the
// newer secret's v1 is the second.
func TestTheDocsVector(t *testing.T) {
	const body = `{"id":"evt_in_01K7XAMPLE00000000000000","object":"event","type":"payment.succeeded","api_version":"2026-10-14.acacia","created":1760000000,"livemode":false,"account":"macc_01K7XAMPLE00000000000000","data":{"object":{"id":"pay_in_01K7XAMPLE00000000000000","object":"payment","amount":49900,"currency":"INR","status":"succeeded"},"previous_attributes":{"status":"processing"}},"request":null,"pending_webhooks":1}`
	const header = "t=1760000000,v1=06309820443c3a8d292dcd2956f6151b52cf7aa4df2f212f6391b36eab245adf,v1=0ea76beaa2f76da27cbc5947a9772534287156d02b13d0ebb0d290a593cb9ecd"
	at := time.Unix(1760000000, 0)
	for _, secret := range []string{"whsec_8Kq3c2Vb7ZpXyN1mT4rLs6Hd9Jf0GwQe", "whsec_1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1u"} {
		if err := Verify(header, []byte(body), secret, Tolerance, at); err != nil {
			t.Errorf("%s: %v", secret, err)
		}
	}
	if got := Sign("whsec_8Kq3c2Vb7ZpXyN1mT4rLs6Hd9Jf0GwQe", at, []byte(body)); got != "t=1760000000,v1=0ea76beaa2f76da27cbc5947a9772534287156d02b13d0ebb0d290a593cb9ecd" {
		t.Errorf("Sign = %s", got)
	}
}
