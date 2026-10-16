// Package signature signs and verifies the PSP-Signature header of a
// webhook delivery: "t=<unix>,v1=<hex>[,v1=<hex>]", each v1 an HMAC-SHA256
// over "<t>.<raw body>" keyed by the whole whsec_ secret.
package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Header is the delivery header that carries the signature.
const Header = "PSP-Signature"

// Tolerance is how far the signed time may be from now, as the docs advise.
const Tolerance = 5 * time.Minute

var (
	ErrMalformed = errors.New("the signature header is malformed")
	ErrTooOld    = errors.New("the signature's timestamp is outside the tolerance")
	ErrMismatch  = errors.New("no signature matches the secret")
)

// Sign returns the header value for body signed with secret at t.
func Sign(secret string, t time.Time, body []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	return "t=" + ts + ",v1=" + mac(secret, ts, body)
}

// Verify checks header against body and secret at now: one v1 of the
// header must match, and its t must be within tolerance of now.
func Verify(header string, body []byte, secret string, tolerance time.Duration, now time.Time) error {
	var ts string
	var sigs []string
	for part := range strings.SplitSeq(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return ErrMalformed
		}
		switch k {
		case "t":
			ts = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(sigs) == 0 {
		return ErrMalformed
	}
	if d := now.Sub(time.Unix(unix, 0)); d > tolerance || d < -tolerance {
		return ErrTooOld
	}
	want := mac(secret, ts, body)
	for _, s := range sigs {
		if hmac.Equal([]byte(s), []byte(want)) {
			return nil
		}
	}
	return ErrMismatch
}

func mac(secret, ts string, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(ts))
	h.Write([]byte{'.'})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
