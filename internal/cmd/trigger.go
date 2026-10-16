package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// fixture is how trigger makes an event happen: a test payment, confirmed
// with a magic UTR or not at all.
type fixture struct {
	about string
	// utr confirms the payment; "" leaves it awaiting the payer, and
	// randomUTR an ordinary UTR of its own.
	utr string
}

const randomUTR = "random"

// fixtures are the events trigger makes, with the magic UTRs of the test
// environment that make them.
var fixtures = map[string]fixture{
	"payment.created":    {about: "a test payment, awaiting the payer"},
	"payment.processing": {about: "a test payment confirmed with a UTR; it succeeds about 5 s later", utr: randomUTR},
	"payment.succeeded":  {about: "a test payment confirmed with the magic UTR 000000000001", utr: "000000000001"},
	"payment.failed":     {about: "a test payment confirmed with the magic UTR 000000000003; it fails about 5 s later", utr: "000000000003"},
}

// currencies are the markets' currencies.
var currencies = map[string]string{"in": "INR"}

func (a *app) triggerCmd() *cobra.Command {
	var overrides []string
	var list bool
	cmd := &cobra.Command{
		Use:   "trigger <event>",
		Short: "Make a test event happen",
		Long: `trigger makes the event happen in test mode the way your integration would:
it creates a test payment with POST /payments and confirms it with a magic
UTR, so the event and every one before it go out as usual, to your
endpoints and to novaro listen.

  novaro trigger payment.succeeded
  novaro trigger payment.created --override amount=50000 --override metadata.order=42

--list shows the events it makes.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if list {
				return cobra.NoArgs(cmd, args)
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return names(), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if list {
				for _, n := range names() {
					fmt.Fprintf(a.out, "%-20s %s\n", n, fixtures[n].about)
				}
				return nil
			}
			fx, ok := fixtures[args[0]]
			if !ok {
				return fmt.Errorf("trigger does not make %q yet; novaro trigger --list shows those it makes", args[0])
			}
			c, err := a.client(false)
			if err != nil {
				return err
			}
			if mode, _, ok := keyParts(c.Key); ok && mode != "test" {
				return errors.New("trigger works in test mode only")
			}
			_, market, _ := keyParts(c.Key)
			body, err := paymentBody(market, overrides)
			if err != nil {
				return err
			}
			var pay struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			}
			if err := c.Do(cmd.Context(), http.MethodPost, "/payments", nil, idempotent(), body, &pay); err != nil {
				return fmt.Errorf("create the payment: %w", err)
			}
			fmt.Fprintf(a.out, "Created payment %s (%s).\n", pay.ID, pay.Status)
			if fx.utr != "" {
				utr := fx.utr
				if utr == randomUTR {
					utr = ordinaryUTR()
				}
				path := "/payments/" + url.PathEscape(pay.ID) + "/confirmations"
				if err := c.Do(cmd.Context(), http.MethodPost, path, nil, idempotent(), map[string]string{"utr": utr}, &pay); err != nil {
					return fmt.Errorf("confirm the payment: %w", err)
				}
				fmt.Fprintf(a.out, "Confirmed it with UTR %s (%s).\n", utr, pay.Status)
			}
			fmt.Fprintf(a.out, "Trigger succeeded: %s is on its way to your endpoints and novaro listen.\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&overrides, "override", nil, "set a field of the payment: amount=50000, customer.email=a@b.c, metadata.k=v")
	cmd.Flags().BoolVar(&list, "list", false, "list the events trigger makes")
	return cmd
}

func names() []string {
	out := make([]string, 0, len(fixtures))
	for n := range fixtures {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// paymentBody is POST /payments' body for a trigger in market, with the
// overrides applied.
func paymentBody(market string, overrides []string) (map[string]any, error) {
	body := map[string]any{
		"amount":              10000,
		"currency":            currencies[market],
		"merchant_reference":  "novaro_trigger_" + randomHex(8),
		"customer":            map[string]any{"id": "novaro_cli"},
		"payment_method_data": map[string]any{"type": "upi", "upi": map[string]any{}},
		"metadata":            map[string]any{"source": "novaro trigger"},
	}
	for _, o := range overrides {
		k, v, ok := strings.Cut(o, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--override %q: want field=value", o)
		}
		path := strings.Split(k, ".")
		var val any = v
		if path[0] != "metadata" {
			val = value(v)
		}
		if err := setPath(body, path, val); err != nil {
			return nil, fmt.Errorf("--override %q: %w", o, err)
		}
	}
	if body["currency"] == "" {
		return nil, errors.New("set the payment's currency: --override currency=…")
	}
	return body, nil
}

// value reads a JSON number, boolean or null as such and anything else as
// a string. metadata's values are strings, whatever they look like.
func value(s string) any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err == nil {
		switch v.(type) {
		case float64, bool, nil:
			return json.RawMessage(s)
		}
	}
	return s
}

func setPath(m map[string]any, path []string, v any) error {
	for i, k := range path {
		if k == "" {
			return errors.New("an empty field name")
		}
		if i == len(path)-1 {
			m[k] = v
			return nil
		}
		next, ok := m[k].(map[string]any)
		if !ok {
			if _, set := m[k]; set {
				return fmt.Errorf("%s is not an object", strings.Join(path[:i+1], "."))
			}
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
	return nil
}

// idempotent is an Idempotency-Key of its own for one POST.
func idempotent() http.Header {
	return http.Header{"Idempotency-Key": []string{"novaro-" + randomHex(16)}}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ordinaryUTR is a 12-digit UTR none of the magic ones (they all start
// 00000000000): 1 to 9, then 11 digits.
func ordinaryUTR() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(9e11))
	return fmt.Sprintf("%012d", n.Int64()+1e11)
}
