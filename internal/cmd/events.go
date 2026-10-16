package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"novaro-cli/internal/api"
)

func (a *app) eventsCmd() *cobra.Command {
	var live bool
	cmd := &cobra.Command{
		Use:   "events",
		Short: "List, read and resend your account's events",
		Long: `events reads your account's events of the last 30 days, as GET /events does,
and resends one to a webhook endpoint.

They are test-mode events unless you pass --live with a live secret key
(--api-key sk_live_…).`,
	}
	cmd.PersistentFlags().BoolVar(&live, "live", false, "live-mode events: needs --api-key sk_live_…")
	client := func() (*api.Client, error) {
		if live {
			if mode, _, ok := keyParts(a.apiKey); !ok || mode != "live" {
				return nil, errors.New("--live needs a live secret key: --api-key sk_live_…")
			}
		}
		return a.client(live)
	}

	var limit int
	var typ, after, before, delivered, gte, lte string
	list := &cobra.Command{
		Use:   "list",
		Short: "List events, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := client()
			if err != nil {
				return err
			}
			q := url.Values{}
			if cmd.Flags().Changed("limit") {
				q.Set("limit", strconv.Itoa(limit))
			}
			set := map[string]string{"type": typ, "starting_after": after, "ending_before": before,
				"delivery_success": delivered, "created[gte]": gte, "created[lte]": lte}
			for k, v := range set {
				if v != "" {
					q.Set(k, v)
				}
			}
			return a.print(cmd.Context(), c, http.MethodGet, "/events", q, nil, nil)
		},
	}
	f := list.Flags()
	f.IntVar(&limit, "limit", 10, "how many, 1 to 100")
	f.StringVar(&typ, "type", "", "only this type, or a group: payment.*")
	f.StringVar(&after, "starting-after", "", "the page after this event id")
	f.StringVar(&before, "ending-before", "", "the page before this event id")
	f.StringVar(&delivered, "delivery-success", "", "true or false: whether every webhook of the event was delivered")
	f.StringVar(&gte, "created-gte", "", "made at or after this unix time")
	f.StringVar(&lte, "created-lte", "", "made at or before this unix time")

	retrieve := &cobra.Command{
		Use:   "retrieve <event id>",
		Short: "Read one event",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client()
			if err != nil {
				return err
			}
			return a.print(cmd.Context(), c, http.MethodGet, "/events/"+url.PathEscape(args[0]), nil, nil, nil)
		},
	}

	var endpoint string
	resend := &cobra.Command{
		Use:   "resend <event id>",
		Short: "Send an event to a webhook endpoint again",
		Long: `resend sends the event to the endpoint again: a new attempt of its delivery,
as Resend in the portal. The endpoint must have been sent the event.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if endpoint == "" {
				return errors.New("--webhook-endpoint is required: the endpoint's id (whe_…), from the portal")
			}
			c, err := client()
			if err != nil {
				return err
			}
			body := map[string]string{"webhook_endpoint": endpoint}
			return a.print(cmd.Context(), c, http.MethodPost, "/events/"+url.PathEscape(args[0])+"/retry", nil, idempotent(), body)
		},
	}
	resend.Flags().StringVar(&endpoint, "webhook-endpoint", "", "the endpoint to send it to (whe_…)")

	cmd.AddCommand(list, retrieve, resend)
	return cmd
}

// print calls the API and writes its answer as indented JSON.
func (a *app) print(ctx context.Context, c *api.Client, method, path string, q url.Values, h http.Header, in any) error {
	var raw json.RawMessage
	if err := c.Do(ctx, method, path, q, h, in, &raw); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		buf.Reset()
		buf.Write(raw)
	}
	_, err := fmt.Fprintln(a.out, strings.TrimRight(buf.String(), "\n"))
	return err
}
